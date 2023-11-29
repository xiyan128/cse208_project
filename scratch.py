import numpy as np
from typing import Literal


def flatten(mat: np.ndarray, order: Literal["C", "F"] = "C") -> np.ndarray:
    return mat.flatten(order=order)

def replicate(vec: np.ndarray, order: Literal["C", "F"] = "C") -> np.ndarray:
    if order == "C":
        # Replicate the vector in C order
        return np.tile(vec, len(vec))
    elif order == "F":
        # Replicate the vector in F order
        return np.repeat(vec, len(vec))
    else:
        raise ValueError("Order must be 'C' or 'F'")


if __name__ == "__main__":
    mat = np.arange(1, 17).reshape(4, 4)
    vec = np.arange(1, 5)

    print(vec @ mat)
    
    flattened_map = flatten(mat, order="F")
    print(flattened_map)
    replicated_vec = replicate(vec, order="F")
    print(replicated_vec)
    
    # use them for vector-matrix multiplication
    prod = flattened_map * replicated_vec
    
    for i in range(4):
        # rotate to the left
        rotated = np.roll(prod, -i * 4)
        print(rotated)
        prod = prod + rotated
        
        
        print(prod)
    
    
    