import numpy as np

class IsolationTree:
    def __init__(self, height_limit):
        self.height_limit = height_limit
        self.size = 0
        self.split_feature = None
        self.split_value = None
        self.left = None
        self.right = None
        self.node_type = 'internal'

    def fit(self, X, current_height=0):
        self.size = len(X)
        
        # Stopping conditions: height limit reached, dataset too small, or identical values
        if current_height >= self.height_limit or self.size <= 1 or np.all(X == X[0]):
            self.node_type = 'external'
            return self

        # Randomly select a feature and a split threshold
        num_features = X.shape[1]
        self.split_feature = np.random.randint(0, num_features)
        
        min_val, max_val = X[:, self.split_feature].min(), X[:, self.split_feature].max()
        if min_val == max_val:
            self.node_type = 'external'
            return self

        self.split_value = np.random.uniform(min_val, max_val)
        
        # Split the data
        left_mask = X[:, self.split_feature] < self.split_value
        self.left = IsolationTree(self.height_limit).fit(X[left_mask], current_height + 1)
        self.right = IsolationTree(self.height_limit).fit(X[~left_mask], current_height + 1)
        
        return self

def path_length(x, tree, current_height):
    if tree.node_type == 'external':
        # Adjustment for external node size (c(n))
        return current_height + c_factor(tree.size)
    
    if x[tree.split_feature] < tree.split_value:
        return path_length(x, tree.left, current_height + 1)
    else:
        return path_length(x, tree.right, current_height + 1)

def c_factor(n):
    if n <= 1: return 0
    return 2 * (np.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)

class MyIsolationForest:
    def __init__(self, n_estimators=100, sample_size=256):
        self.n_estimators = n_estimators
        self.sample_size = sample_size
        self.trees = []

    def fit(self, X):
        self.trees = []
        self._sample_size = min(self.sample_size, len(X))
        self.limit = np.ceil(np.log2(self._sample_size))
        for _ in range(self.n_estimators):
            # Sampling for each tree
            idx = np.random.choice(len(X), self._sample_size, replace=False)
            tree = IsolationTree(self.limit).fit(X[idx])
            self.trees.append(tree)
        return self

    def decision_function(self, X):
        lengths = []
        for x in X:
            avg_length = np.mean([path_length(x, t, 0) for t in self.trees])
            lengths.append(avg_length)
        
        # Calculate the anomaly score: 2^(-E(h(x))/c(n))
        c = c_factor(self._sample_size)
        scores = 2 ** -(np.array(lengths) / c)
        return scores