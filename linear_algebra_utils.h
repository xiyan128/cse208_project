#pragma once

#include "openfhe.h"
#include <vector>


using namespace lbcrypto;
using namespace std;

std::vector<std::vector<double_t>> zeroExtend(
        std::vector<std::vector<double_t>> mat,
        size_t numRows,
        size_t numCols
) {
    for (auto &row: mat) row.resize(numCols, 0);
    mat.resize(numRows, std::vector<double_t>(numCols, 0));
    return mat;
}

enum class FlattenOrder {
    RowMajor,
    ColumnMajor
};

// flatten a mat into a vector
template<typename T>
vector<T> flatten(const vector<vector<T>> &mat, const FlattenOrder order = FlattenOrder::RowMajor) {
    vector<T> result;
    if (order == FlattenOrder::RowMajor) {
        for (auto &row: mat) {
            result.insert(result.end(), row.begin(), row.end());
        }
    } else {
        for (size_t i = 0; i < mat[0].size(); i++) {
            for (size_t j = 0; j < mat.size(); j++) {
                result.push_back(mat[j][i]);
            }
        }
    }
    return result;
}


template<typename T>
T bitCeil(T x) {
    if (x == 0) return 1;
    T result = 1;
    while (result < x) result <<= 1;
    return result;
}


Ciphertext<DCRTPoly>
replicate(const CryptoContext<DCRTPoly> &cc, const Ciphertext<DCRTPoly> &vec, size_t n_rows, ::size_t n_cols) {
    auto result = vec;

    for (size_t i = 0; i < log2(n_cols); i++)
        result = cc->EvalAdd(result, cc->EvalRotate(result, -(n_rows << i)));

    return result;

}


Ciphertext<DCRTPoly> MultVectorMatrixCP(
        const CryptoContext<DCRTPoly> &cc,
        PublicKey<DCRTPoly> pk,
        Ciphertext<DCRTPoly> vec,
        std::vector<std::vector<double_t>> mat,
        bool transposing
) {
    size_t num_rows_ = mat.size();
    size_t num_cols_ = mat[0].size();

    auto num_rows = bitCeil(num_rows_);
    auto num_cols = bitCeil(num_cols_);

    mat = zeroExtend(mat, num_rows, num_cols);

    std::vector<::double_t> matFlat = flatten(mat, FlattenOrder::ColumnMajor);

    Plaintext matFlatP = cc->MakeCKKSPackedPlaintext(matFlat);

    vec = replicate(cc, vec, num_rows, num_cols_);

    Ciphertext<DCRTPoly> prod = cc->EvalMult(vec, matFlatP);
    for (size_t i = 0; i < log2(num_rows); i++)
        prod = cc->EvalAdd(prod, cc->EvalRotate(prod, 1 << i));

    if (transposing) {
        const std::vector<double_t> ZERO = {0};
        const Plaintext ZERO_PLAINTEXT = cc->MakeCKKSPackedPlaintext(ZERO);
        Ciphertext<DCRTPoly> res = cc->Encrypt(pk, ZERO_PLAINTEXT);
        std::vector<double_t> mask = {1};
        Plaintext maskP;
        for (size_t i = 0; i < num_cols_; i++) {
            maskP = cc->MakeCKKSPackedPlaintext(mask);
            res = cc->EvalAdd(res, cc->EvalMult(
                    cc->EvalRotate(
                            prod,
                            i * (num_rows - 1)),
                    maskP));
            mask.insert(mask.begin(), 0);
        }
        prod = res;
    }

    return prod;
}
