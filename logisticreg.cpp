#include <vector>
#include "openfhe.h"
#include "linear_algebra_utils.h"
#include <iostream>
#include <fstream>
#include <cmath>

#define VECTOR_SIZE 4
using namespace lbcrypto;

CryptoContext<DCRTPoly> InitializeScheme() {
    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetPlaintextModulus(536903681);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 11);

#if NATIVEINT == 128
    usint scalingModSize = 78;
    usint firstModSize   = 89;
#else
    usint scalingModSize = 50;
    usint firstModSize = 60;
#endif

    uint32_t multDepth = 100; //might need to change this for weird errors

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
EncryptVector(const std::vector<double> &vec, const CryptoContext<DCRTPoly> &cryptoContext,
              const KeyPair<DCRTPoly> &keyPair) {

    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(vec);
    return cryptoContext->Encrypt(keyPair.publicKey, plaintext);
}

Ciphertext<DCRTPoly>
HomomorphicDotProduct(const CryptoContext<DCRTPoly> &cryptoContext, const Ciphertext<DCRTPoly> &encryptedVector1,
                      const Ciphertext<DCRTPoly> &encryptedVector2) {
    return cryptoContext->EvalInnerProduct(encryptedVector1, encryptedVector2, VECTOR_SIZE);
}

Ciphertext<DCRTPoly>
HomomorphicLogisticRegression(const CryptoContext<DCRTPoly> &cryptoContext, const Ciphertext<DCRTPoly> &encryptedVector) {
    double lowerBound = 0;
    double upperBound = 1;
    uint32_t logisticDegree = 100; // Adjust as needed
    return cryptoContext->EvalLogistic(encryptedVector, lowerBound, upperBound, logisticDegree);
}

double DotProduct(const std::vector<double> &vec1, const std::vector<double> &vec2) {
    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must be equal");
    }

    // use std::inner_product to compute the dot product
    double dotProduct = std::inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0);
    return dotProduct;
}

// Function to calculate logistic function output
double calculateLogisticOutput(const std::vector<double>& weights, const std::vector<double>& data) {
    // Calculate dot product between weights and data vector
    double dotProduct = 0.0;
    for (size_t i = 0; i < data.size(); ++i) {
        dotProduct += weights[i] * data[i];
    }

    // Calculate logistic function 1 / (1 + e^(-x))
    return 1.0 / (1.0 + std::exp(-dotProduct));
}

std::vector<double> readWeightsFromFile(const std::string& filename) {
    std::vector<double> weights;

    // Open the file
    std::ifstream file(filename);

    // Check if the file is opened successfully
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return weights; // Return an empty vector
    }

    // Read values from the file into the vector
    double value;
    while (file >> value) {
        weights.push_back(value);
    }

    // Close the file
    file.close();

    return weights;
}
void readTestDataFromFile(const std::string& filename,
                          std::vector<std::vector<double>>& rows, std::vector<double>& nthValues) {
    // Open the file
    std::ifstream file(filename);

    // Check if the file is opened successfully
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return; // Return without modifying the vectors
    }

    // Read 30 rows of data
    for (int i = 0; i < 30; ++i) {
        // Vector to store n values for the current row
        std::vector<double> rowData;

        // Read n values from the current row
        for (int j = 0; j < VECTOR_SIZE; ++j) {
            double value;
            file >> value;
            rowData.push_back(value);
        }

        // Read and store the (n+1)th value for the current row
        double nthValue;
        file >> nthValue;
        nthValues.push_back(nthValue);

        // Store the n values for the current row in the array of vectors
        rows.push_back(rowData);
    }

    // Close the file
    file.close();
}
int main(){
    // Construct the file name
    std::string dir = "/Users/chhaviyadav/Downloads/cse208_project/";
    std::string filename = dir+"weights_" + std::to_string(VECTOR_SIZE) + "D.txt";
    std::vector<double> weights = readWeightsFromFile(filename);

    // Print the values in the vector
    std::cout << "Values read from the file:" << std::endl;
    for (const auto& w : weights) {
        std::cout << w << " ";
    }
    std::cout << std::endl;

    std::string testDataFilename = dir+"test_data_" + std::to_string(VECTOR_SIZE) + "D.txt";

    // Vectors to store (n+1)th values and n values for each row
    std::vector<double> nthValues;
    std::vector<std::vector<double>> rows;

    // Call the function to read test data from the file
    readTestDataFromFile(testDataFilename, rows, nthValues);

    // Print the values read from the file
    std::cout << "30 Rows of (n+1)th values:" << std::endl;
    for (const auto& nth : nthValues) {
        std::cout << nth << " ";
    }
    std::cout << std::endl;

    std::cout << "Array of Vectors (30 Rows, n Values Each):" << std::endl;
    for (const auto& row : rows) {
        for (const auto& value : row) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }

    CryptoContext<DCRTPoly> cryptoContext = InitializeScheme();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int32_t> indexList = {};
    for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 10; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList); //for inner product

    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET slBin = TOY;
    uint32_t logQ_ccLWE = 25;
    uint32_t slots = 4;

    auto FHEWparams = cryptoContext->EvalCKKStoFHEWSetup(sl, slBin, false, logQ_ccLWE, false, slots);
    auto ccLWE = FHEWparams.first;
    auto privateKeyFHEW = FHEWparams.second;
    cryptoContext->EvalCKKStoFHEWKeyGen(keyPair, privateKeyFHEW);
    cryptoContext->EvalSchemeSwitchingKeyGen(keyPair, privateKeyFHEW, 4, true, true);

    auto pLWE1 = ccLWE.GetMaxPlaintextSpace().ConvertToInt();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContext->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;

    double scaleSign = 512.0;
    cryptoContext->EvalCompareSwitchPrecompute(pLWE1, init_level, scaleSign);

    // Encrypt vectors
    for (const auto& row : rows) {
        auto encryptedVector1 = EncryptVector(row, cryptoContext, keyPair);
        auto encryptedVector2 = EncryptVector(weights, cryptoContext, keyPair);

        auto dotProduct = HomomorphicDotProduct(cryptoContext, encryptedVector1, encryptedVector2);
        auto logisticout = HomomorphicLogisticRegression(cryptoContext, dotProduct);

        Plaintext logisticout_clear;
        cryptoContext->Decrypt(keyPair.secretKey, logisticout, &logisticout_clear);
        logisticout_clear->SetLength(1);
        std::cout << "Homomorphic Logistic function output: " << logisticout_clear << std::endl;


        double logisticOutput = calculateLogisticOutput(weights, row);
        std::cout << "In clear Logistic function output: " << logisticOutput << std::endl;
    }

    return 0;
}
