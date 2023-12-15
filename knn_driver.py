import itertools
import subprocess
import pandas as pd
import json

if __name__ == "__main__":
    # run test_cosine_similarity with arguments -f example_{size}.csv -k {k}
    # files are in knn_data
    # executable in build
    sizes = [32]
    ks = [1, 3, 5, 7, 9, 11]

    df = pd.DataFrame(
        columns=['size', 'k', 'encrypt_time', 'mip_time', 'k_largest_time', 'classification_time', 'decrypt_time',
                 'total_time'])

    for size, k in itertools.product(sizes, ks):
        print(f"Running test for size {size} and k {k}")
        output = subprocess.check_output(
            ["./build/test_cosine_similarity", "-f", f"knn_data/example_{size}.csv", "-k", str(k)]
        )

        output = output.decode("utf-8")
        # parse json
        output = json.loads(output)
        print(output)
        # add to dataframe
        df = pd.concat([df, pd.DataFrame(output | {'size': size, 'k': k}, index=[0])])

    df.to_csv("results_ks.csv", index=False)
