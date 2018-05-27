using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SHA3;
using HashLib;

namespace ELearningCryptography.Encryption
{
    public static class Cryptography
    {
        public class Aes
        {
            #region Settings

            private static int _iterations = 2;
            private static int _keySize = 256;

            private static string _hash = "SHA1";
            private static string _salt = "aselrias38490a32"; // Random
            private static string _vector = "8947az34awl34kjq"; // Random

            #endregion

            public static string Encrypt(string value, string password)
            {
                return Encrypt<AesManaged>(value, password);
            }
            public static string Encrypt<T>(string value, string password)
                    where T : SymmetricAlgorithm, new()
            {
                byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
                byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
                byte[] valueBytes = Encoding.UTF8.GetBytes(value);

                byte[] encrypted;
                using (T cipher = new T())
                {
                    PasswordDeriveBytes _passwordBytes =
                        new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                    byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                    cipher.Mode = CipherMode.CBC;

                    using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
                    {
                        using (MemoryStream to = new MemoryStream())
                        {
                            using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                            {
                                writer.Write(valueBytes, 0, valueBytes.Length);
                                writer.FlushFinalBlock();
                                encrypted = to.ToArray();
                            }
                        }
                    }
                    cipher.Clear();
                }
                return Convert.ToBase64String(encrypted);
            }

            public static string Decrypt(string value, string password)
            {
                return Decrypt<AesManaged>(value, password);
            }
            public static string Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
            {
                byte[] vectorBytes = Encoding.ASCII.GetBytes(_vector);
                byte[] saltBytes = Encoding.ASCII.GetBytes(_salt);
                byte[] valueBytes = Convert.FromBase64String(value);

                byte[] decrypted;
                int decryptedByteCount = 0;

                using (T cipher = new T())
                {
                    PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);
                    byte[] keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                    cipher.Mode = CipherMode.CBC;

                    try
                    {
                        using (ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
                        {
                            using (MemoryStream from = new MemoryStream(valueBytes))
                            {
                                using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                                {
                                    decrypted = new byte[valueBytes.Length];
                                    decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        return String.Empty;
                    }

                    cipher.Clear();
                }
                return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
            }
        }
        
        public class Des
        {

            public static string Encrypt(string originalString)
            {
                byte[] secretKey = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

                if (String.IsNullOrEmpty(originalString))
                {
                    throw new ArgumentNullException
                           ("The string which needs to be encrypted can not be null.");
                }
                var cryptoProvider = new DESCryptoServiceProvider();
                var memoryStream = new MemoryStream();
                var cryptoStream = new CryptoStream(memoryStream,
                    cryptoProvider.CreateEncryptor(secretKey, secretKey), CryptoStreamMode.Write);
                var writer = new StreamWriter(cryptoStream);
                writer.Write(originalString);
                writer.Flush();
                cryptoStream.FlushFinalBlock();
                writer.Flush();
                return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
            }

            public static string Decrypt(string cryptedString)
            {
                byte[] secretKey = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
                

                if (String.IsNullOrEmpty(cryptedString))
                {
                    throw new ArgumentNullException
                       ("The string which needs to be decrypted can not be null.");
                }
                var cryptoProvider = new DESCryptoServiceProvider();
                var memoryStream = new MemoryStream
                        (Convert.FromBase64String(cryptedString));
                var cryptoStream = new CryptoStream(memoryStream,
                    cryptoProvider.CreateDecryptor(secretKey, secretKey), CryptoStreamMode.Read);
                var reader = new StreamReader(cryptoStream);
                return reader.ReadToEnd();
            }

        }

        public class Rsa
        {
            public static string Encrypt(string strText, int keySize)
            {
                var publicKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

                var data = Encoding.UTF8.GetBytes(strText);

                using (var rsa = new RSACryptoServiceProvider(keySize))
                {
                    try
                    {
                        // client encrypting data with public key issued by server                    
                        rsa.FromXmlString(publicKey.ToString());

                        var encryptedData = rsa.Encrypt(data, true);

                        var base64Encrypted = Convert.ToBase64String(encryptedData);

                        return base64Encrypted;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }

            public static string Decrypt(string strText, int keySiza)
            {
                var privateKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent><P>/aULPE6jd5IkwtWXmReyMUhmI/nfwfkQSyl7tsg2PKdpcxk4mpPZUdEQhHQLvE84w2DhTyYkPHCtq/mMKE3MHw==</P><Q>3WV46X9Arg2l9cxb67KVlNVXyCqc/w+LWt/tbhLJvV2xCF/0rWKPsBJ9MC6cquaqNPxWWEav8RAVbmmGrJt51Q==</Q><DP>8TuZFgBMpBoQcGUoS2goB4st6aVq1FcG0hVgHhUI0GMAfYFNPmbDV3cY2IBt8Oj/uYJYhyhlaj5YTqmGTYbATQ==</DP><DQ>FIoVbZQgrAUYIHWVEYi/187zFd7eMct/Yi7kGBImJStMATrluDAspGkStCWe4zwDDmdam1XzfKnBUzz3AYxrAQ==</DQ><InverseQ>QPU3Tmt8nznSgYZ+5jUo9E0SfjiTu435ihANiHqqjasaUNvOHKumqzuBZ8NRtkUhS6dsOEb8A2ODvy7KswUxyA==</InverseQ><D>cgoRoAUpSVfHMdYXW9nA3dfX75dIamZnwPtFHq80ttagbIe4ToYYCcyUz5NElhiNQSESgS5uCgNWqWXt5PnPu4XmCXx6utco1UVH8HGLahzbAnSy6Cj3iUIQ7Gj+9gQ7PkC434HTtHazmxVgIR5l56ZjoQ8yGNCPZnsdYEmhJWk=</D></RSAKeyValue>";

                var data = Encoding.UTF8.GetBytes(strText);

                using (var rsa = new RSACryptoServiceProvider(keySiza))
                {
                    try
                    {
                        var base64Encrypted = strText;

                        // server decrypting data with private key                    
                        rsa.FromXmlString(privateKey);

                        var resultBytes = Convert.FromBase64String(base64Encrypted);
                        var decryptedBytes = rsa.Decrypt(resultBytes, true);
                        var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                        return decryptedData.ToString();
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
        }

        public class Md5
        {
            public static string Hash(string input)
            {
                // Use input string to calculate MD5 hash
                using (var md5 = MD5.Create())
                {
                    byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);

                    // Convert the byte array to hexadecimal string
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        sb.Append(hashBytes[i].ToString("X2"));
                    }
                    return sb.ToString();
                }
            }

            public static async Task<string> ReverseMd5(string value)
            {
                var str = await GetReverseMd5(value);
                return str;
            }

            private static async Task<string> GetReverseMd5(string value)
            {
                try
                {
                    var client = new HttpClient();
                    var code = "5105ff6d435b0cec";

                    var urlString = "http://md5decrypt.net/Api/api.php?hash="+ value + "&hash_type=md5&email=dannsilverbrown@gmail.com&code=" + code;
                    
                    var uri = new Uri(urlString);
                    var str = await client.GetStringAsync(uri);
                    return str;
                }
                catch (Exception ex)
                {
                    return "";
                }
            }

        }

        public class Sha1
        {
            public static string Hash(string input)
            {
                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                    var sb = new StringBuilder(hash.Length * 2);

                    foreach (byte b in hash)
                    {
                        // can be "x2" if you want lowercase
                        sb.Append(b.ToString("X2"));
                    }

                    return sb.ToString();
                }
            }
        }

        public class Sha2
        {
            public static string Hash(string value, string keySize)
            {
                byte[] data = Encoding.ASCII.GetBytes(value);

                switch (keySize)
                {
                    case "256":
                        var alg = SHA256.Create();
                        alg.ComputeHash(data);
                        return BitConverter.ToString(alg.Hash);
                    case "384":
                        var Alg = SHA384.Create();
                        Alg.ComputeHash(data);
                        return BitConverter.ToString(Alg.Hash);
                    case "512":
                        var Alg1 = SHA512.Create();
                        Alg1.ComputeHash(data);
                        return BitConverter.ToString(Alg1.Hash);
                    default:
                        return "";
                }
                
                
            }
        }

        public class Sha3
        {
            public static string Hash(string value)
            {
                IHash hash = HashFactory.Crypto.SHA3.CreateKeccak512();
                var hashAlgo = HashFactory.Wrappers.HashToHashAlgorithm(hash);
                byte[] input = Encoding.UTF8.GetBytes(value);
                byte[] output = hashAlgo.ComputeHash(input);
                var sb = new StringBuilder(2048);

                foreach (byte b in output)
                {
                    // can be "x2" if you want lowercase
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }

        public class DiffieHellman : IDisposable
        {
            private AesCryptoServiceProvider aes = null;
            private ECDiffieHellmanCng diffieHellman = null;

            private readonly byte[] publicKey;

            public DiffieHellman()
            {
                this.aes = new AesCryptoServiceProvider();

                this.diffieHellman = new ECDiffieHellmanCng
                {
                    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                    HashAlgorithm = CngAlgorithm.Sha256
                };

                // This is the public key we will send to the other party
                this.publicKey = this.diffieHellman.PublicKey.ToByteArray();
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            protected virtual void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (this.aes != null)
                        this.aes.Dispose();

                    if (this.diffieHellman != null)
                        this.diffieHellman.Dispose();
                }
            }

            public byte[] PublicKey
            {
                get
                {
                    return this.publicKey;
                }
            }

            public byte[] IV
            {
                get
                {
                    return this.aes.IV;
                }
            }

            public string Encrypt(byte[] publicKey, string secretMessage)
            {
                byte[] encryptedMessage;
                var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
                var derivedKey = diffieHellman.DeriveKeyMaterial(key); // "Common secret"

                aes.Key = derivedKey;

                using (var cipherText = new MemoryStream())
                {
                    using (var encryptor = aes.CreateEncryptor())
                    {
                        using (var cryptoStream = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                            cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                        }
                    }

                    encryptedMessage = cipherText.ToArray();
                }

                var sb = new StringBuilder(2048);
                foreach (byte b in encryptedMessage)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();

            }

            public string Decrypt(byte[] publicKey, string encMessage, byte[] iv)
            {
                byte[] encryptedMessage = Encoding.UTF8.GetBytes(encMessage);
                string decryptedMessage;
                var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
                var derivedKey = this.diffieHellman.DeriveKeyMaterial(key);

                aes.Key = derivedKey;
                aes.IV = iv;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using (var plainText = new MemoryStream())
                {
                    using (var decryptor = this.aes.CreateDecryptor())
                    {
                        using (var cryptoStream = new CryptoStream(plainText, decryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(encryptedMessage, 0, encryptedMessage.Length);
                        }
                    }

                    var sb = new StringBuilder(2048);
                    foreach (byte b in plainText.ToArray())
                    {
                        sb.Append(b.ToString("X2"));
                    }
                    decryptedMessage =  sb.ToString();
                }

                return decryptedMessage;
            }


        }

    }
}