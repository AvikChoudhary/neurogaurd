"""
A small, dependency-free (NumPy only) feed-forward Artificial Neural Network.

It is deliberately implemented from scratch so it runs identically on Windows,
macOS and Linux without TensorFlow/PyTorch wheels, and so every step (forward
pass, back-propagation, Adam optimiser) can be explained in a presentation.

Two tasks are supported by the same class:
  * task="classify"     : ReLU hidden layers + softmax output, cross-entropy loss
  * task="autoencoder"  : ReLU hidden layers + linear output, mean-squared-error loss
"""
import numpy as np


def softmax(z):
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


class MLP:
    def __init__(self, sizes, task="classify", dropout=0.0, l2=1e-5, seed=7):
        self.sizes = list(sizes)
        self.task = task
        self.dropout = float(dropout)
        self.l2 = float(l2)
        rng = np.random.default_rng(seed)
        self.W = [rng.normal(0.0, np.sqrt(2.0 / self.sizes[i]), (self.sizes[i], self.sizes[i + 1]))
                  for i in range(len(self.sizes) - 1)]          # He initialisation
        self.b = [np.zeros(self.sizes[i + 1]) for i in range(len(self.sizes) - 1)]
        self.L = len(self.W)

    # ------------------------------------------------------------------ forward
    def _forward(self, X, train=False, rng=None):
        a, cache = X, []
        for i in range(self.L):
            z = a @ self.W[i] + self.b[i]
            if i < self.L - 1:
                a_next = np.maximum(z, 0.0)
                mask = None
                if train and self.dropout > 0:
                    mask = (rng.random(a_next.shape) >= self.dropout) / (1.0 - self.dropout)
                    a_next = a_next * mask
                cache.append((a, z, mask))
                a = a_next
            else:
                cache.append((a, z, None))
                a = z
        return a, cache

    def embed(self, X):
        """Activations of the last hidden layer (the network's learned representation of a flow)."""
        a = X
        for i in range(self.L - 1):
            a = np.maximum(a @ self.W[i] + self.b[i], 0.0)
        return a

    def logits(self, X):
        return self._forward(X)[0]

    def predict_proba(self, X):
        return softmax(self.logits(X))

    def reconstruct(self, X):
        return self.logits(X)

    def param_count(self):
        return int(sum(w.size for w in self.W) + sum(b.size for b in self.b))

    # ----------------------------------------------------------------- training
    def _loss_grad(self, out, X, y, w):
        n = len(X)
        if self.task == "classify":
            p = softmax(out)
            loss = float(np.mean(-np.log(p[np.arange(n), y] + 1e-12) * w))
            d = p.copy()
            d[np.arange(n), y] -= 1.0
            return loss, d * (w[:, None] / n)
        diff = out - X
        return float(np.mean(diff ** 2)), 2.0 * diff / (n * X.shape[1])

    def _backward(self, d, cache):
        gW, gb = [None] * self.L, [None] * self.L
        for i in range(self.L - 1, -1, -1):
            a_in, z, _ = cache[i]
            gW[i] = a_in.T @ d + self.l2 * self.W[i]
            gb[i] = d.sum(axis=0)
            if i > 0:
                d = d @ self.W[i].T
                d = d * (cache[i - 1][1] > 0)
                if cache[i - 1][2] is not None:
                    d = d * cache[i - 1][2]
        return gW, gb

    def evaluate(self, X, y=None):
        out = self.logits(X)
        w = np.ones(len(X))
        loss, _ = self._loss_grad(out, X, y, w)
        acc = float(np.mean(out.argmax(1) == y)) if self.task == "classify" else None
        return loss, acc

    def fit(self, X, y=None, Xv=None, yv=None, epochs=40, batch=256, lr=2e-3, patience=7,
            class_weight=None, seed=0, callback=None):
        rng = np.random.default_rng(seed)
        n = len(X)
        mW = [np.zeros_like(w) for w in self.W]; vW = [np.zeros_like(w) for w in self.W]
        mb = [np.zeros_like(b) for b in self.b]; vb = [np.zeros_like(b) for b in self.b]
        b1, b2, eps, t = 0.9, 0.999, 1e-8, 0
        hist = {"loss": [], "val_loss": [], "acc": [], "val_acc": []}
        best, best_w, wait = np.inf, None, 0
        cw = np.ones(int(y.max()) + 1) if (class_weight is None and y is not None) else class_weight

        for ep in range(1, epochs + 1):
            step_lr = lr * (0.5 * (1 + np.cos(np.pi * (ep - 1) / epochs)) * 0.9 + 0.1)  # cosine decay
            idx = rng.permutation(n)
            tot, correct = 0.0, 0
            for s in range(0, n, batch):
                bi = idx[s:s + batch]
                xb = X[bi]
                yb = y[bi] if y is not None else None
                wb = cw[yb] if (self.task == "classify") else np.ones(len(bi))
                out, cache = self._forward(xb, train=True, rng=rng)
                loss, d = self._loss_grad(out, xb, yb, wb)
                gW, gb = self._backward(d, cache)
                t += 1
                for i in range(self.L):
                    for p, g, m, v in ((self.W, gW, mW, vW), (self.b, gb, mb, vb)):
                        m[i] = b1 * m[i] + (1 - b1) * g[i]
                        v[i] = b2 * v[i] + (1 - b2) * g[i] ** 2
                        p[i] -= step_lr * (m[i] / (1 - b1 ** t)) / (np.sqrt(v[i] / (1 - b2 ** t)) + eps)
                tot += loss * len(bi)
                if self.task == "classify":
                    correct += int((out.argmax(1) == yb).sum())
            tr_loss = tot / n
            tr_acc = correct / n if self.task == "classify" else None
            if Xv is not None:
                v_loss, v_acc = self.evaluate(Xv, yv)
            else:
                v_loss, v_acc = tr_loss, tr_acc
            hist["loss"].append(tr_loss); hist["val_loss"].append(v_loss)
            hist["acc"].append(tr_acc); hist["val_acc"].append(v_acc)
            if callback:
                callback(ep, epochs, tr_loss, v_loss, tr_acc, v_acc)
            if v_loss < best - 1e-5:
                best, wait = v_loss, 0
                best_w = ([w.copy() for w in self.W], [b.copy() for b in self.b])
            else:
                wait += 1
                if wait >= patience:
                    break
        if best_w:
            self.W, self.b = best_w
        return hist

    # ------------------------------------------------------------ explainability
    def input_gradient(self, X, cls):
        """d logit[cls] / d input  (saliency), used for gradient x input attributions."""
        a, masks = X, []
        for i in range(self.L - 1):
            z = a @ self.W[i] + self.b[i]
            masks.append(z > 0)
            a = np.maximum(z, 0)
        g = np.zeros((len(X), self.sizes[-1]))
        g[np.arange(len(X)), cls] = 1.0
        for i in range(self.L - 1, -1, -1):
            g = g @ self.W[i].T
            if i > 0:
                g = g * masks[i - 1]
        return g

    # ------------------------------------------------------------- persistence
    def state(self, prefix):
        d = {f"{prefix}_sizes": np.array(self.sizes), f"{prefix}_task": np.array(self.task)}
        for i in range(self.L):
            d[f"{prefix}_W{i}"] = self.W[i]
            d[f"{prefix}_b{i}"] = self.b[i]
        return d

    @classmethod
    def from_state(cls, d, prefix):
        m = cls([int(s) for s in d[f"{prefix}_sizes"]], task=str(d[f"{prefix}_task"]))
        m.W = [d[f"{prefix}_W{i}"] for i in range(m.L)]
        m.b = [d[f"{prefix}_b{i}"] for i in range(m.L)]
        return m
