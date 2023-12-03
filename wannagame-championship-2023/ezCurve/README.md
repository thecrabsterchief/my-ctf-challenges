# ezCurve

- Category: Crypto
- Score: 489/500
- Solves: 6
- Flag: `W1{P3ll_Curv3_1s_fun_r1ght?_532e3a90d802f4a3e3ce25b5f72d93d4}`

## Description

Can you see that? It's not too complicated!

## Solution

The first thing you need to do is figure out what the curve look like. To do this, take a look at `generate_parameters` method:

$$
y = \dfrac{1 \pm \sqrt{k + (1 - k)x^{2}}}{x(k - 1)} \pmod{p}
$$

After performing algebraic transformations, we end up with

$$
\left(\dfrac{1}{x} + y\right)^{2} - ky^{2} = 1
$$


which is sth like... a Pell's equation. So we've found the mapping that transform the original curve to **"Pell Curve"**: $(x, y) \rightarrow \left( \dfrac{1}{x} + y\right)$

P/s: You also realize my intended mapping on these lines of code:

```python
    # so weirddd :<
    return Point(inverse_mod(x - y, self.p), y)
```

Now we need to compute the actual discrete logarithm to recover the flag. The well known method used here is trying to find homomorphism, then traffer DLP on curve (which is pretty hard) to DLP on some other Field (which is considered much easier)

P/s: I recommend you read this [paper](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.66.8688&rep=rep1&type=pdf) before reading the rest.

From the given $k$ and $p$ values you can see that:

- $\binom{k}{p} = -1 \qquad$ [Legendre symbol](https://en.wikipedia.org/wiki/Legendre_symbol)
- $p + 1$ is smooth

So use the homomorphic mapping from above paper:

$$
\begin{align*}
&\phi: &\left(\mathbb{C}, +\right) &\mapsto \left(\mathbb{F}_{p}[x]/(x^2 - k), \times\right) \\
&\phi: &(a, b) &\mapsto (a + bx)
\end{align*}
$$

For more details, see my [full script](./solve.sage)