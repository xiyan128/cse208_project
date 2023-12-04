#include <vector>
#include "openfhe.h"
#include "linear_algebra_utils.h"

using namespace lbcrypto;

#define VECTOR_SIZE 3

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

    uint32_t multDepth = 18;

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

double DotProduct(const std::vector<double> &vec1, const std::vector<double> &vec2) {
    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must be equal");
    }

    // use std::inner_product to compute the dot product
    double dotProduct = std::inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0);
    return dotProduct;
}

Ciphertext<DCRTPoly> HomomorphicVectorLength(const CryptoContext<DCRTPoly> &cryptoContext,
                                             const Ciphertext<DCRTPoly> &encryptedVector) {
    // Homomorphically square each element and sum
    auto squared = cryptoContext->EvalSquare(encryptedVector);
    auto sumOfSquares = cryptoContext->EvalSum(squared, VECTOR_SIZE);

    // Apply Chebyshev approximation for square root
    double lowerBound = 0;
    double upperBound = VECTOR_SIZE;
    uint32_t polyDegree = 25; // Adjust as needed

    auto length = cryptoContext->EvalChebyshevFunction(
            [](double x) -> double { return std::sqrt(x); },
            sumOfSquares,
            lowerBound,
            upperBound,
            polyDegree
    );

    return length;
}

double VectorLength(const std::vector<double> &vec) {
    // use std::inner_product to compute the sum of squares
    double sumOfSquares = std::inner_product(vec.begin(), vec.end(), vec.begin(), 0.0);

    // take the square root
    double length = std::sqrt(sumOfSquares);
    return length;
}

Ciphertext<DCRTPoly> HomomorphicCosineSimilarity(const CryptoContext<DCRTPoly> &cryptoContext,
                                                 const Ciphertext<DCRTPoly> &encryptedVector1,
                                                 const Ciphertext<DCRTPoly> &encryptedVector2) {
    // Compute the dot product
    auto dotProduct = HomomorphicDotProduct(cryptoContext, encryptedVector1, encryptedVector2);

    // Compute the vector lengths
    auto length1 = HomomorphicVectorLength(cryptoContext, encryptedVector1);
    auto length2 = HomomorphicVectorLength(cryptoContext, encryptedVector2);

    // Divide the dot product by the product of the vector lengths
    auto lengthProduct = cryptoContext->EvalMult(length1, length2);

    double lowerBound = 0;
    double upperBound = 1;
    uint32_t divideDegree = 25; // Adjust as needed

    auto inverseLengthProduct = cryptoContext->EvalDivide(lengthProduct, lowerBound, upperBound, divideDegree);

    auto cosineSimilarity = cryptoContext->EvalMult(dotProduct, inverseLengthProduct);

    return dotProduct;
}

double CosineSimilarity(const std::vector<double> &vec1,
                        const std::vector<double> &vec2) {
    if (vec1.size() != vec2.size()) {
        throw std::invalid_argument("Vector sizes must be equal");
    }

    double dotProduct = DotProduct(vec1, vec2);

    double length1 = VectorLength(vec1);

    double length2 = VectorLength(vec2);

    return dotProduct / (length1 * length2);
}

Ciphertext<DCRTPoly> KLargestMask(const CryptoContext<DCRTPoly> &cryptoContext,
                                  const PublicKey<DCRTPoly> publicKey,
                                  const Ciphertext<DCRTPoly> &encryptedVector,
                                  uint32_t k,
                                  uint32_t numValues = 0,
                                  uint32_t pLWE = 0, double scaleSign = 1.0
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

int main() {
    // Example vectors
    std::vector<double> vector1 = {0.1, 0.2, 0.3};
    std::vector<double> vector2 = {0.4, 0.5, 0.6};


    // Initialize the encryption scheme
    CryptoContext<DCRTPoly> cryptoContext = InitializeScheme();

    // Generate keys
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);

    std::vector<int32_t> indexList = {};
    for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 10; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);

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
    auto encryptedVector1 = EncryptVector(vector1, cryptoContext, keyPair);
    auto encryptedVector2 = EncryptVector(vector2, cryptoContext, keyPair);

//    std::vector<std::vector<double_t>> matrix = {
//                                                 {0.2672612419124244, 0.5345224838248488, 0.8017837257372732},
//                                                 {0.9733285267845753, 0.16222142113076254, 0.16222142113076254},
//                                                 {0.9091372900969896, 0.40406101782088427, 0.10101525445522107}};


    std::vector<std::vector<double_t>> matrix = {
            {0.9733285267845753, 0.16222142113076254, 0.16222142113076254},
            {0.2672612419124244, 0.5345224838248488,  0.8017837257372732},
    };


    Plaintext decryptedResult;

    auto res = MultVectorMatrixCP(cryptoContext, keyPair.publicKey, encryptedVector1, matrix, true);


    auto mask = KLargestMask(cryptoContext, keyPair.publicKey, res, 3, 4, pLWE1, scaleSign);

    cryptoContext->Decrypt(keyPair.secretKey, mask, &decryptedResult);

    std::cout << "Max Index: " << decryptedResult << std::endl;

    // (ConstCiphertext<Element> ciphertext, PublicKey<Element> publicKey, uint32_t numValues = 0, uint32_t numSlots = 0, bool oneHot = true, uint32_t pLWE = 0, double scaleSign = 1.0)
//    auto max_res = cryptoContext->EvalMaxSchemeSwitching(res, keyPair.publicKey, 4, 4, true, 0, 100.0);


//    auto val = max_res[0], idx = max_res[1];
//
//    cryptoContext->Decrypt(keyPair.secretKey, val, &decryptedResult);
//    std::cout << "Max Value: " << decryptedResult << std::endl;
//
//    cryptoContext->Decrypt(keyPair.secretKey, idx, &decryptedResult);
//    std::cout << "Max Index: " << decryptedResult << std::endl;
//
//
//    cryptoContext->Decrypt(keyPair.secretKey, res, &decryptedResult);
//
//    std::cout << "Dot Product: " << decryptedResult;








//
//    // Compute the homomorphic dot product
//    Ciphertext<DCRTPoly> encryptedDotProduct = HomomorphicDotProduct(cryptoContext, encryptedVector1, encryptedVector2);
//
//    // Decrypt the result (optional, for verification)
//    Plaintext decryptedResult;
//    cryptoContext->Decrypt(keyPair.secretKey, encryptedDotProduct, &decryptedResult);
//    decryptedResult->SetLength(1); // We are only interested in the first slot of the result
//
//    std::cout << "Dot Product: " << decryptedResult;
//    std::cout << "Dot Product (plaintext): " << DotProduct(vector1, vector2) << std::endl;
//
//
//    // Compute the homomorphic vector length
//    Ciphertext<DCRTPoly> encryptedVectorLength = HomomorphicVectorLength(cryptoContext, encryptedVector1);
//
//    // Decrypt the result (optional, for verification)
//    cryptoContext->Decrypt(keyPair.secretKey, encryptedVectorLength, &decryptedResult);
//    decryptedResult->SetLength(1);
//
//    std::cout << "Vector Length: " << decryptedResult;
//    std::cout << "Vector Length (plaintext): " << VectorLength(vector1) << std::endl;
//
//    // Compute the homomorphic cosine similarity
//    Ciphertext<DCRTPoly> encryptedCosineSimilarity = HomomorphicCosineSimilarity(cryptoContext, encryptedVector1, encryptedVector2);
//
//    // Decrypt the result (optional, for verification)
//    cryptoContext->Decrypt(keyPair.secretKey, encryptedCosineSimilarity, &decryptedResult);
//    decryptedResult->SetLength(1);
//
//    std::cout << "Cosine Similarity: " << decryptedResult;
//    std::cout << "Cosine Similarity (plaintext): " << CosineSimilarity(vector1, vector2) << std::endl;

    return 0;
}