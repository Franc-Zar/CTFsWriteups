import itertools

# Function to find all subsets of size k with a target sum
def find_subsets_with_sum(arr, k, target_sum):
    iterations = 0
    # Initialize an empty list to store valid subsets
    valid_subsets = []

    # Use itertools.combinations to generate all combinations of size k
    for subset in itertools.combinations(arr, k):
        if sum(subset) == target_sum:
            print(f"found a valid subset at iteration: {iterations}")
            valid_subsets.append(subset)
        iterations += 1
    print(f"total iterations: {iterations}")
    return valid_subsets


choices = [19728964, 30673077, 137289540, 195938621, 207242611, 237735979, 298141799, 302597011, 387047012, 405520686, 424852916, 461998372, 463977415, 528505766, 557896298, 603269308, 613528675, 621228168, 654758801, 670668388, 741571487, 753993381, 763314787, 770263388, 806543382, 864409584, 875042623, 875651556, 918697500, 946831967]
target = 7627676296

valid_subsets = find_subsets_with_sum(arr=choices, k=15, target_sum=target)

for subset in valid_subsets:
    print(subset)
    flag = "UDCTF{%s}" % ("_".join(map(str,subset)))
    print(flag)
    
    # (19728964, 30673077, 137289540, 195938621, 237735979, 302597011, 463977415, 603269308, 654758801, 670668388, 763314787, 806543382, 875651556, 918697500, 946831967)
    # UDCTF{19728964_30673077_137289540_195938621_237735979_302597011_463977415_603269308_654758801_670668388_763314787_806543382_875651556_918697500_946831967}