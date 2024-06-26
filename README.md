# Elliptic Curve

Nói nghe thì có vẻ ghê gớm nhưng mà elliptic curve nó ghê gớm thực sự :)) 

### Elliptic Curve definition

Elliptic Curve là 1 đường cong trơn dưới dạng pt: $y^2 = x^3 + ax + b$

Trong mật mã học, Elliptic Curve sẽ được tính toán trong trường hữu hạn thay vì trường số thực

Nếu ta coi mỗi điểm trên elliptic curve tương ứng với 1 element , thì elliptic curve khi này sẽ tạo thành 1 group structure, tức là nó thỏa mãn các tính chất cơ bản của group.

Vậy thì operation trên elliptic curve tính toán ra sao? Mình hơi lười nên sẽ để link để bạn tự tìm hiểu:[https://en.wikipedia.org/wiki/Elliptic_curve](https://en.wikipedia.org/wiki/Elliptic_curve#:~:text=In%20mathematics%2C%20an%20elliptic%20curve,product%20of%20K%20with%20itself)

### Point addition

### Point doubling

### Point multiplication (with scalar)

## Thuật toán tấn công ECDLP

Cho tới thời điểm hiện tại, không tồn tại 1 thuật toán hiệu quả nào có thể solve ECDLP trong thời gian tuyến tính. Tuy nhiên, nếu như các tham số của curve bị setup sai (cryptographic failure) thì hoàn toàn có thể tấn công curve .

### Smooth order

Cũng giống như bài toán discrete logarithm trên trường hữu hạn, 1 curve với smooth order hoàn toàn có thể attack tương tự áp dụng Pohlig Hellman.

- B1: Chuyển bài toán $k.G = P$ lên subgroup order
- B2: Sử dụng thuật toán BSGS để tìm k trên subgroup order ( gọi các subgroup lần lượt có order là $n_1, n_2, n_3, ... n_m$ và các $k$ lần lượt ta tìm được trên các subgroup tương ứng là $k_1, k_2, k_3,..., k_m$)
- Sử dụng thuật toán crt để tổng hợp lại các group order

Thật may là trên sagemath có sẵn 1 hàm để tính toán DLP trên Elliptic Curve

Dưới đây là 1 code mẫu ví dụ:

```python
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

Fp = GF(p)
ec = EllipticCurve(Fp, [a, b])

Px, Py = 0, 0# define your point here
Gx, Gy = 0, 0
P = ec(Px, Py)
G = ec(Gx, Gy)

print(discrete_log(P, G, operation = "+"))
```

### Small scalar

Hệ số nhỏ cũng là 1 nguyên nhân dẫn tới có thể tấn công.

Ở đây mình giả sử rằng : $n = a_1.a_2.a_3...a_m$, và $a_1.a_2.a_3...a_j >=k$ (với điều kiện là $a_1,a_2,a_3,...a_j$ đều là smooth number)

Đặt $s = a_1.a_2.a_3...a_j$, ta sẽ tìm kiếm $k'$ của pt $kG=P$ trên order $s$

Vì $s>=k$ nên $k'=k$

### Bruteforce

Bruteforce tìm secret thôi :)), bộ môn nào cx cần biết kỹ năng brute này