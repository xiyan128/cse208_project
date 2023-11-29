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

    uint32_t multDepth = 15;

    parameters.SetScalingModSize(scalingModSize);
    parameters.SetFirstModSize(firstModSize);

    // need to set this, otherwise get "Removing last element of DCRTPoly object renders it invalid!"
    parameters.SetMultiplicativeDepth(multDepth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
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





//    std::vector<int32_t> indices = {1, 2, 3};
//    cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, indices);

    std::vector<int32_t> indexList = {};
    for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 10; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);

    // Encrypt vectors
    auto encryptedVector1 = EncryptVector(vector1, cryptoContext, keyPair);
    auto encryptedVector2 = EncryptVector(vector2, cryptoContext, keyPair);

    std::vector<std::vector<double_t>> matrix = {{1, 2, 3},
                                                 {4, 5, 6},
                                                 {7, 8, 9}};




    // template<typename T = ::double_t>
    //Ciphertext<DCRTPoly> MultVectorMatrixCP(
    //        const CryptoContext<DCRTPoly> &cc,
    //        const Ciphertext<DCRTPoly> &vec,
    //                                        const vector<vector<T>> &matrix


    // Decrypt the result (optional, for verification)

    Plaintext decryptedResult;

    auto res = MultVectorMatrixCP(cryptoContext, keyPair.publicKey, encryptedVector1, matrix, true);

    // Decrypt the result (optional, for verification)

    cryptoContext->Decrypt(keyPair.secretKey, res, &decryptedResult);

    std::cout << "Dot Product: " << decryptedResult;

    // a larger example with 100 rows and 1000 columns
    std::vector<std::vector<double_t>> largeMatrix(22, std::vector<double_t>(22, 1));
    // large vector
    std::vector<double_t> largeVector(22, 1);
    // encrypt the vector
    auto encryptedLargeVector = EncryptVector(largeVector, cryptoContext, keyPair);

    auto largeRes = MultVectorMatrixCP(cryptoContext, keyPair.publicKey, encryptedLargeVector, largeMatrix, false);

    // Decrypt the result (optional, for verification)
    cryptoContext->Decrypt(keyPair.secretKey, largeRes, &decryptedResult);
    std::cout << "Dot Product: " << decryptedResult;





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