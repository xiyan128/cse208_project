#include <vector>
#include "openfhe.h"
#include "linear_algebra_utils.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <chrono>

#define VECTOR_SIZE 32
using namespace lbcrypto;

CryptoContext<DCRTPoly> InitializeScheme() {
    std::cout << "In  Logistic init " << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;

    //parameters.SetPlaintextModulus(536903681);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 10);

#if NATIVEINT == 128
    usint scalingModSize = 78;
    usint firstModSize   = 89;
#else
    usint scalingModSize = 50;
    usint firstModSize = 60;
#endif

    uint32_t multDepth = 13; //might need to change this for weird errors how many times can you multiply ciphertexts

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
    return cryptoContext->EvalInnerProduct(encryptedVector1, encryptedVector2, VECTOR_SIZE+1);
}

Ciphertext<DCRTPoly>
HomomorphicLogisticRegression(const CryptoContext<DCRTPoly> &cryptoContext, const Ciphertext<DCRTPoly> &encryptedVector) {
    double lowerBound = -4; // these are on the domain?
    double upperBound = 4;
    uint32_t logisticDegree = 12; // Adjust as needed - degree of polynomial higher is better approx
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
double calculateAverage(const std::vector<long long>& numbers) {
    if (numbers.empty()) {
        std::cerr << "Error: Vector is empty." << std::endl;
        return 0.0; // Return 0 if the vector is empty to avoid division by zero
    }

    long long sum = 0;

    // Calculate the sum of all elements
    for (const auto& num : numbers) {
        sum += num;
    }

    // Calculate the average
    double average = static_cast<double>(sum) / numbers.size();

    return average;
}
// Function to calculate logistic function output
double calculateLogisticOutput(const std::vector<double>& weights, const std::vector<double>& data) {
    // Calculate dot product between weights and data vector
    double dotProduct = 0.0;
    for (size_t i = 0; i < data.size(); ++i) {
        dotProduct += weights[i] * data[i];
    }
    std::cout << "Dot product: " << dotProduct << " ";
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
                          std::vector<std::vector<double>>& rows, std::vector<double>& labels) {
    // Open the file
    std::ifstream file(filename);

    // Check if the file is opened successfully
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return; // Return without modifying the vectors
    }

    // Read 30 rows of data
    for (int i = 0; i < 30; ++i) {
        // Vector to store n+1 values for the current row
        std::vector<double> rowData;

        // Read n+1 values from the current row (first n+1 columns)
        for (int j = 0; j < VECTOR_SIZE + 1; ++j) {
            double value;
            file >> value;
            rowData.push_back(value);
        }

        // Read and store the label (n+2th column) for the current row
        double label;
        file >> label;
        labels.push_back(label);

        // Store the n+1 values for the current row in the array of vectors
        rows.push_back(rowData);
    }

    // Close the file
    file.close();
}

double calculateSimilarityPercentage(const std::vector<int>& predicted, const std::vector<double>& labels) {
    // Ensure that the vectors have the same size
    if (predicted.size() != labels.size()) {
        std::cerr << "Error: Vectors must have the same size." << std::endl;
        return -1.0; // Return a negative value to indicate an error
    }

    // Count the number of matching predictions
    int matchingCount = 0;
    for (size_t i = 0; i < predicted.size(); ++i) {
        if (predicted[i] == labels[i]) {
            matchingCount++;
        }
    }

    // Calculate the percentage of similar predictions
    double similarityPercentage = (static_cast<double>(matchingCount) / predicted.size()) * 100.0;

    return similarityPercentage;
}

int main(){
    // Construct the file name
    std::string dir = "/Users/chhaviyadav/Downloads/cse208_project/";
    std::string filename = dir+"weights_" + std::to_string(VECTOR_SIZE) + "D.txt";
    std::vector<double> weights = readWeightsFromFile(filename);
    std::ofstream outFile(dir+"output_"+std::to_string(VECTOR_SIZE)+"D.txt");

    // Print the values in the vector
    std::cout << "Values read from the file:" << std::endl;
    for (const auto& w : weights) {
        std::cout << w << " ";
    }
    std::cout << std::endl;

    std::string testDataFilename = dir+"test_data_" + std::to_string(VECTOR_SIZE) + "D.txt";

    // Vectors to store (n+1)th values and n values for each row
    std::vector<std::vector<double>> rows;
    std::vector<double> labels;

    readTestDataFromFile(testDataFilename, rows, labels);

    // Print the read data for verification
    for (int i = 0; i < 30; ++i) {
        std::cout << "Row " << i + 1 << ": ";
        for (int j = 0; j < VECTOR_SIZE + 1; ++j) {
            std::cout << rows[i][j] << " ";
        }
        std::cout << "Label: " << labels[i] << std::endl;
    }

    CryptoContext<DCRTPoly> cryptoContext = InitializeScheme();
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalSumKeyGen(keyPair.secretKey);
    /*std::vector<int32_t> indexList = {};
    for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 10; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList); //for inner product


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
    double scaleSign = 512.0;
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContext->GetCryptoParameters());
    ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
    uint32_t init_level = 0;
    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cryptoContext->EvalCompareSwitchPrecompute(pLWE1, init_level, scaleSign);*/
    std::vector<int> outputArray;
    std::vector<long long> encryptionT, decryptionT, dotpdtT,logisticT, cleardptlogisticT;

    // Encrypt vectors
    for (const auto& row : rows) {
        auto start_time_encryption = std::chrono::high_resolution_clock::now();
        auto encryptedVector1 = EncryptVector(row, cryptoContext, keyPair);
        auto encryptedVector2 = EncryptVector(weights, cryptoContext, keyPair);
        auto end_time_encryption = std::chrono::high_resolution_clock::now();
        auto duration_encryption = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_encryption - start_time_encryption).count();
        encryptionT.push_back(duration_encryption);

        auto start_time_dotPdt = std::chrono::high_resolution_clock::now();
        auto dotProduct = HomomorphicDotProduct(cryptoContext, encryptedVector1, encryptedVector2);
        auto end_time_dotPdt = std::chrono::high_resolution_clock::now();
        auto duration_dtpdt = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_dotPdt - start_time_dotPdt).count();
        dotpdtT.push_back(duration_dtpdt);

        auto start_time_logistic = std::chrono::high_resolution_clock::now();
        auto logisticout = HomomorphicLogisticRegression(cryptoContext, dotProduct);
        auto end_time_logistic = std::chrono::high_resolution_clock::now();
        auto duration_logistic = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_logistic - start_time_logistic).count();
        logisticT.push_back(duration_logistic);

        Plaintext dotpdt_clear;
        cryptoContext->Decrypt(keyPair.secretKey, dotProduct, &dotpdt_clear);
        dotpdt_clear->SetLength(1);

        auto start_time_decryption= std::chrono::high_resolution_clock::now();
        Plaintext logisticout_clear;
        cryptoContext->Decrypt(keyPair.secretKey, logisticout, &logisticout_clear);
        logisticout_clear->SetLength(1);
        std::vector<std::complex<double>> finalResult = logisticout_clear->GetCKKSPackedValue();
        double finallogval = finalResult[0].real();
        auto end_time_decryption= std::chrono::high_resolution_clock::now();
        auto duration_decryption = std::chrono::duration_cast<std::chrono::milliseconds>(end_time_decryption - start_time_decryption).count();
        decryptionT.push_back(duration_decryption);

        std::cout << "Homomorphic Dot Product function output: " << dotpdt_clear << std::endl;
        std::cout << "Decrypted Logistic function: " << finallogval << std::endl;

        auto start_time_cleardptlog = std::chrono::high_resolution_clock::now();
        double logisticOutput = calculateLogisticOutput(weights, row);
        auto end_time_cleardptlog = std::chrono::high_resolution_clock::now();
        auto duration_cleardptlog = std::chrono::duration_cast<std::chrono::microseconds>(end_time_cleardptlog - start_time_cleardptlog).count();
        cleardptlogisticT.push_back(duration_cleardptlog);

        std::cout << "In clear Logistic function output: " << logisticOutput << std::endl;

        std::cout << "Comparison: " << finallogval << " " << logisticOutput << std::endl;
        if (finallogval >= 0.5) {
            outputArray.push_back(1);
        } else {
            outputArray.push_back(0);
        }

        /*std::vector<double> vec = {0.5, finalResult[0].real()};
        auto encryptedOutputVector = EncryptVector(vec, cryptoContext, keyPair);
        uint32_t numValues = 2;
        std::cout <<"Sending vector in" << vec << encryptedOutputVector << std::endl;
        auto max_res = cryptoContext->EvalMaxSchemeSwitching(
                encryptedOutputVector,
                keyPair.publicKey,
                numValues,
                numValues,
                true,
                pLWE1, scaleSign
        );*/


    }
    std::cout << "predicted : " << outputArray << std::endl;
    std::cout <<" labels : " << labels <<std::endl;
    double acc = calculateSimilarityPercentage(outputArray, labels);

    std::cout << "Dimension: " << VECTOR_SIZE << std::endl;
    std::cout << "Accuracy: " << acc << "%" << std::endl;
    std::cout << "Encryption time in millisec: " << calculateAverage(encryptionT) << std::endl;
    std::cout << "Decryption time in millisec: " << calculateAverage(decryptionT)<< std::endl;
    std::cout << "Logistic time in millisec: " << calculateAverage(logisticT)<< std::endl;
    std::cout << "Dtpdt time in millisec: " << calculateAverage(dotpdtT)<< std::endl;
    std::cout << "Clear Dtpdt& Logistic time in microsec: " << calculateAverage(cleardptlogisticT)<< std::endl;

    outFile << "Dimension: " << VECTOR_SIZE << std::endl;
    outFile << "Accuracy: " << acc << "%" << std::endl;
    outFile << "Encryption time in millisec: " << calculateAverage(encryptionT) << std::endl;
    outFile << "Decryption time in millisec: " << calculateAverage(decryptionT) << std::endl;
    outFile << "Logistic time in millisec: " << calculateAverage(logisticT) << std::endl;
    outFile << "Dtpdt time in millisec: " << calculateAverage(dotpdtT) << std::endl;
    outFile << "Clear Dtpdt& Logistic time in microsec: " << calculateAverage(cleardptlogisticT) << std::endl;

    // Close the file
    outFile.close();

    return 0;
}
