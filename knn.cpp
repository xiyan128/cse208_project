#include <vector>
#include "openfhe.h"
#include "linear_algebra_utils.h"
#include <chrono>
#include "rapidcsv.h"
#include "cxxopts.hpp"
#include <iostream>

using namespace lbcrypto;

#define VECTOR_SIZE 3

CryptoContext<DCRTPoly> InitializeScheme() {
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetPlaintextModulus(536903681);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    usint scalingModSize = 78;
    usint firstModSize   = 89;
#else
    usint scalingModSize = 50;
    usint firstModSize = 60;
#endif

    const uint32_t multDepth = 50;

    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);

    // need to set this, otherwise get "Removing last element of DCRTPoly object renders it invalid!"
    parameters.SetMultiplicativeDepth(multDepth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(SCHEMESWITCH);
    return cryptoContext;
}

Ciphertext<DCRTPoly>
EncryptVector(const std::vector<double>& vec, const CryptoContext<DCRTPoly>& cryptoContext,
              const KeyPair<DCRTPoly>& keyPair) {
    const Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vec);
    return cryptoContext->Encrypt(keyPair.publicKey, plaintext);
}

Ciphertext<DCRTPoly>
HomomorphicDotProduct(const CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly>& encryptedVector1,
                      const Ciphertext<DCRTPoly>& encryptedVector2) {
    return cryptoContext->EvalInnerProduct(encryptedVector1, encryptedVector2, VECTOR_SIZE);
}

double DotProduct(const std::vector<double>& vec1, const std::vector<double>& vec2) {
    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must be equal");
    }

    // use std::inner_product to compute the dot product
    const double dotProduct = std::inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0);
    return dotProduct;
}

Ciphertext<DCRTPoly> HomomorphicVectorLength(const CryptoContext<DCRTPoly>& cryptoContext,
                                             const Ciphertext<DCRTPoly>& encryptedVector) {
    // Homomorphically square each element and sum
    const auto squared = cryptoContext->EvalSquare(encryptedVector);
    const auto sumOfSquares = cryptoContext->EvalSum(squared, VECTOR_SIZE);

    // Apply Chebyshev approximation for square root
    const double lowerBound = 0;
    const double upperBound = VECTOR_SIZE;
    const uint32_t polyDegree = 25; // Adjust as needed

    auto length = cryptoContext->EvalChebyshevFunction(
        [](const double x) -> double { return std::sqrt(x); },
        sumOfSquares,
        lowerBound,
        upperBound,
        polyDegree
    );

    return length;
}

double VectorLength(const std::vector<double>& vec) {
    // use std::inner_product to compute the sum of squares
    const double sumOfSquares = std::inner_product(vec.begin(), vec.end(), vec.begin(), 0.0);

    // take the square root
    const double length = std::sqrt(sumOfSquares);

    return length;
}

Ciphertext<DCRTPoly> HomomorphicCosineSimilarity(const CryptoContext<DCRTPoly>& cryptoContext,
                                                 const Ciphertext<DCRTPoly>& encryptedVector1,
                                                 const Ciphertext<DCRTPoly>& encryptedVector2) {
    // Compute the dot product
    auto dotProduct = HomomorphicDotProduct(cryptoContext, encryptedVector1, encryptedVector2);

    // Compute the vector lengths
    const auto length1 = HomomorphicVectorLength(cryptoContext, encryptedVector1);
    const auto length2 = HomomorphicVectorLength(cryptoContext, encryptedVector2);

    // Divide the dot product by the product of the vector lengths
    const auto lengthProduct = cryptoContext->EvalMult(length1, length2);

    const double lowerBound = 0;
    const double upperBound = 1;
    const uint32_t divideDegree = 25; // Adjust as needed

    const auto inverseLengthProduct = cryptoContext->EvalDivide(lengthProduct, lowerBound, upperBound, divideDegree);

    auto cosineSimilarity = cryptoContext->EvalMult(dotProduct, inverseLengthProduct);

    return dotProduct;
}

double CosineSimilarity(const std::vector<double>& vec1,
                        const std::vector<double>& vec2) {
    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must be equal");
    }

    const double dotProduct = DotProduct(vec1, vec2);

    const double length1 = VectorLength(vec1);

    const double length2 = VectorLength(vec2);

    return dotProduct / (length1 * length2);
}

Ciphertext<DCRTPoly> KLargestMask(const CryptoContext<DCRTPoly>& cryptoContext,
                                  const PublicKey<DCRTPoly> publicKey,
                                  const Ciphertext<DCRTPoly>& encryptedVector,
                                  uint32_t k,
                                  const uint32_t numValues = 0,
                                  const uint32_t pLWE = 0, const double scaleSign = 1.0
) {
    if (k > numValues) {
        throw std::invalid_argument("k must be less than or equal to the number of values");
    }
    // run EvalMaxSchemeSwitching for k times and accumulate the mask
    Ciphertext<DCRTPoly> mask;
    Ciphertext<DCRTPoly> vec = encryptedVector;
    cryptoContext->ModReduceInPlace(vec);

    while (k--) {
        auto max_res = cryptoContext->EvalMaxSchemeSwitching(
            vec,
            publicKey,
            numValues,
            numValues,
            true,
            pLWE, scaleSign
        );

        auto val = max_res[0], idx = max_res[1];

        if (mask == nullptr) {
            mask = idx;
        } else {
            mask = cryptoContext->EvalAdd(mask, idx);
        }

        auto mask_neg = cryptoContext->EvalSub(1, idx);
        vec = cryptoContext->EvalMult(mask_neg, vec);
    }

    return mask;
}


void ReadCSV(const std::string& filePath, std::vector<std::vector<double>>& matrix, std::vector<double>& labels,
             FlattenOrder order = FlattenOrder::RowMajor) {
    const rapidcsv::Document doc(filePath, rapidcsv::LabelParams(-1, -1));

    size_t numRows = doc.GetRowCount();
    size_t numCols = doc.GetColumnCount();

    matrix.clear();
    matrix.reserve(numRows);
    labels.clear();
    labels.reserve(numRows);

    for (size_t rowIdx = 0; rowIdx < numRows; ++rowIdx) {
        std::vector<double> row;
        row.reserve(numCols - 1);

        for (size_t colIdx = 0; colIdx < numCols - 1; ++colIdx) {
            row.push_back(doc.GetCell<double>(colIdx, rowIdx));
        }

        labels.push_back(doc.GetCell<double>(numCols - 1, rowIdx));
        matrix.push_back(row);
    }

    if (order == FlattenOrder::ColumnMajor) {
        // Transpose the matrix for column-major order
        std::vector<std::vector<double>> transposedMatrix(numCols - 1, std::vector<double>(numRows));

        for (size_t i = 0; i < numRows; ++i) {
            for (size_t j = 0; j < numCols - 1; ++j) {
                transposedMatrix[j][i] = matrix[i][j];
            }
        }
        matrix = std::move(transposedMatrix);

        assert(labels.size() == numCols - 1);
    } else {
        assert(labels.size() == numRows);
    }
}


int main(int argc, char* argv[]) {
    // Example vectors
    std::vector<double> vector1 = {0.3355906, 0.12398129, 0.5404281};
    //    std::vector<double> vector2 = {0.4, 0.5, 0.6};

    cxxopts::Options options("CSVReader", "Reads knn_data from a CSV file");

    // Define options
    options.add_options()
            ("f,file", "CSV file path", cxxopts::value<std::string>())
            ("k,knn", "k nearest neighbors", cxxopts::value<int>()->default_value("1"))
            ("h,help", "Print usage");


    // Variables to store parsed values
    std::string filePath;
    int k = 1;
    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("file")) {
            filePath = result["file"].as<std::string>();
        } else {
            std::cerr << "No CSV file provided. Use -f option." << std::endl;
            return 1;
        }

        if (result.count("knn")) {
            k = result["knn"].as<int>();
        }
    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    }

    std::vector<std::vector<double>> matrix;
    std::vector<double> labels;


    try {
        ReadCSV(filePath, matrix, labels);

        // print the matrix
        std::cerr << "Matrix: " << std::endl;
        for (const auto& row: matrix) {
            for (const auto& val: row) {
                std::cerr << val << " ";
            }
            std::cerr << std::endl;
        }

        // print the labels
        std::cerr << "Labels: " << std::endl;
        for (const auto& label: labels) {
            std::cerr << label << " ";
        }
        std::cerr << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }


    const auto N = matrix.size();
    auto top_k = k;


    // Initialize the encryption scheme
    CryptoContext<DCRTPoly> cryptoContext = InitializeScheme();

    // Generate keys
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);

    std::vector<int32_t> indexList = {};
    int eval_range = vector1.size() * N;

    std::cerr << "eval_range: " << eval_range << std::endl;

    for (int i = -eval_range; i <= eval_range; i++) indexList.push_back(i);
    for (int i = 0; i <= 30; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }

    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);

    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE = 25;
    uint32_t slots = bitCeil(N);

    auto FHEWparams = cryptoContext->EvalCKKStoFHEWSetup(sl, slBin, false, logQ_ccLWE, false, slots);
    auto ccLWE = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    cryptoContext->EvalCKKStoFHEWKeyGen(keyPair, privateKeyFHEW);
    cryptoContext->EvalSchemeSwitchingKeyGen(keyPair, privateKeyFHEW, top_k, true, false);

    auto pLWE1 = ccLWE.GetMaxPlaintextSpace().ConvertToInt();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContext->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;

    double scaleSign = 512.0;
    cryptoContext->EvalCompareSwitchPrecompute(pLWE1, init_level, scaleSign);


    /* ------------------ */
    /* ---- ENCRYPT ------ */

    auto start = std::chrono::high_resolution_clock::now();

    // Encrypt vectors
    auto encryptedVector1 = EncryptVector(vector1, cryptoContext, keyPair);
    //    auto encryptedVector2 = EncryptVector(vector2, cryptoContext, keyPair);

    auto encryptedLabels = EncryptVector(labels, cryptoContext, keyPair);

    auto end = std::chrono::high_resolution_clock::now();
    auto encrypt_time = (end - start).count();

    /* ------------------ */
    /* ---- COMPUTE ------ */

    start = std::chrono::high_resolution_clock::now();
    auto res = MultVectorMatrixCP(cryptoContext, keyPair.publicKey, encryptedVector1, matrix, true);
    end = std::chrono::high_resolution_clock::now();
    auto mip_time = (end - start).count();


    start = std::chrono::high_resolution_clock::now();
    auto mask = KLargestMask(cryptoContext, keyPair.publicKey, res, top_k, bitCeil(N), pLWE1, scaleSign);
    end = std::chrono::high_resolution_clock::now();

    auto k_largest_time = (end - start).count();

    start = std::chrono::high_resolution_clock::now();
    auto classification_res = cryptoContext->EvalMult(cryptoContext->EvalInnerProduct(encryptedLabels, mask, 3),
                                                      1.0 / top_k);
    end = std::chrono::high_resolution_clock::now();
    auto classification_time = (end - start).count();

    /* ------------------ */
    /* ---- DECRYPT ------ */

    start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedResult;
    cryptoContext->Decrypt(keyPair.secretKey, classification_res, &decryptedResult);
    decryptedResult->SetLength(1);
    end = std::chrono::high_resolution_clock::now();
    auto decrypt_time = (end - start).count();


    // std::cout << "classification result: " << decryptedResult << std::endl;
    //
    // std::cout << "encrypt time: " << encrypt_time << std::endl;
    // std::cout << "mip time: " << mip_time << std::endl;
    // std::cout << "k largest time: " << k_largest_time << std::endl;
    // std::cout << "classification time: " << classification_time << std::endl;
    // std::cout << "decrypt time: " << decrypt_time << std::endl;

    std::cout << "{";
    std::cout << "\"encrypt_time\": " << encrypt_time << ", ";
    std::cout << "\"mip_time\": " << mip_time << ", ";
    std::cout << "\"k_largest_time\": " << k_largest_time << ", ";
    std::cout << "\"classification_time\": " << classification_time << ", ";
    std::cout << "\"decrypt_time\": " << decrypt_time << ", ";
    std::cout << "\"total_time\": " << encrypt_time + mip_time + k_largest_time + classification_time + decrypt_time << ", ";
    std::cout << "\"result\": " << decryptedResult->GetPackedValue()[0];
    std::cout << "}" << std::endl;
    return 0;
};
