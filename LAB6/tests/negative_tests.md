# Lab 6 — Correctness & Negative Tests

Đáp ứng spec §4 Lab 6. Toàn bộ chạy qua KAT runner trong CLI.

## ML-DSA — `MLDSA kat --algo mldsa-44`

| # | Case | Spec §4 case | Expected |
|---|---|---|---|
| 1 | positive roundtrip | Correctness | sign → verify OK |
| 2 | modified message rejected | "Modified message → fail" | verify FAIL |
| 3 | modified signature rejected | "Modified signature → fail" | verify FAIL |
| 4 | wrong public key rejected | "Modified public key → fail" | verify FAIL |
| 5 | truncated signature rejected | (fail-closed bonus) | verify FAIL |
| 6 | wrong private key (cross-pair) | "Wrong private key → fail" | verify FAIL |
| 7 | malformed key file rejected | (fail-closed bonus) | throw |
| 8 | wrong algorithm identifier (44↔65) | "Wrong algorithm identifier" | verify FAIL |

→ 8/8 PASS.

## ML-KEM — `MLKEM kat --algo mlkem-512`

| # | Case | Spec §4 case | Expected |
|---|---|---|---|
| 1 | positive encaps/decaps SS match | Correctness | shared secret giống nhau |
| 2 | wrong private key → SS khác | "Wrong private key → fail" | SS không match (FO implicit rejection) |
| 3 | modified ciphertext → SS khác | "Modified ciphertext (KEM) → fail" | SS không match |
| 4 | truncated ciphertext rejected | (fail-closed bonus) | decaps throw |
| 5 | malformed key file rejected | (fail-closed bonus) | throw |
| 6 | wrong algorithm identifier (512↔768) | "Wrong algorithm identifier" | decaps throw |

→ 6/6 PASS.

## Ghi chú về ML-KEM "wrong private key"

Khác với chữ ký, ML-KEM **không throw** khi private key sai — nó áp dụng
**Fujisaki-Okamoto implicit rejection**: decaps trả ra một shared secret
ngẫu nhiên hợp lệ về mặt định dạng, nhưng khác với SS thật. Test 2 và 3
verify hành vi này bằng cách so sánh byte SS với SS đúng (phải khác).

Đây là tính chất bảo mật **IND-CCA** của ML-KEM — không tiết lộ cho
attacker biết "ciphertext này có hợp lệ không".
