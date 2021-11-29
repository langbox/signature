# 说明
golang SHA256withECDSA 算法

## 例子

```
str := "abc"
privateKey := "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDL9833IX0JVALjoeB1StEOUtTnLhHsQ3eds2Y47IEE-A"
sign,_ := signature.SignECDSA(str, privateKey)
fmt.Println(sign)
```
