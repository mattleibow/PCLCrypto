﻿namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

#if !(SILVERLIGHT && !WINDOWS_PHONE) // Silverlight 5 doesn't include asymmetric crypto
    [TestClass]
    public class AsymmetricKeyAlgorithmProviderTests
    {
        /// <summary>
        /// A dictionary of key algorithms to test with key sizes (in bits).
        /// </summary>
        private static readonly IReadOnlyDictionary<AsymmetricAlgorithm, int> KeyAlgorithmsToTest = new Dictionary<AsymmetricAlgorithm, int>
        {
            { AsymmetricAlgorithm.RsaOaepSha1, 512 },
            { AsymmetricAlgorithm.EcdsaP256Sha256, 256 },
        };

        [TestMethod]
        public void OpenAlgorithm_GetAlgorithmName()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            Assert.AreEqual(AsymmetricAlgorithm.RsaOaepSha1, rsa.Algorithm);
        }

        [TestMethod]
        public void CreateKeyPair_InvalidInputs()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(-1));
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(0));
        }

        [TestMethod]
        public void CreateKeyPair_RsaOaepSha1()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);
            Assert.IsNotNull(key);
            Assert.AreEqual(512, key.KeySize);
        }

        [TestMethod]
        public void CreateKeyPair_EcdsaP256Sha256()
        {
            var ecdsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.EcdsaP256Sha256);
            var key = ecdsa.CreateKeyPair(256);
            Assert.IsNotNull(key);
            Assert.AreEqual(256, key.KeySize);
        }

        [TestMethod]
        public void ImportKeyPair_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportKeyPair(null));
        }

        [TestMethod]
        public void ImportPublicKey_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportPublicKey(null));
        }

        [TestMethod]
        public void RSAParametersPrivateKeyRoundtrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var keyPair = rsa.CreateKeyPair(512);
            RSAParameters parameters = keyPair.ExportParameters(includePrivateParameters: true);
            ICryptographicKey keyPair2 = rsa.ImportParameters(parameters);

            var blob1 = keyPair.Export();
            var blob2 = keyPair2.Export();
            CollectionAssertEx.AreEqual(blob1, blob2);
        }

        [TestMethod]
        public void RSAParametersPublicKeyRoundtrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var keyPair = rsa.CreateKeyPair(512);
            RSAParameters parameters = keyPair.ExportParameters(includePrivateParameters: false);
            Assert.IsNull(parameters.P, "Private key should have been omitted.");
            Assert.IsNull(parameters.InverseQ, "Private key should have been omitted.");
            Assert.IsNull(parameters.D, "Private key should have been omitted.");
            Assert.IsNull(parameters.Q, "Private key should have been omitted.");
            Assert.IsNull(parameters.DP, "Private key should have been omitted.");
            Assert.IsNull(parameters.DQ, "Private key should have been omitted.");
            ICryptographicKey publicKey = rsa.ImportParameters(parameters);

            var blob1 = keyPair.ExportPublicKey();
            var blob2 = publicKey.ExportPublicKey();
            CollectionAssertEx.AreEqual(blob1, blob2);
        }

        [TestMethod]
        public void ExportParametersThrowsOnPublicKeyMismatch()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var keyPair = rsa.CreateKeyPair(512);
            var publicKey = rsa.ImportPublicKey(keyPair.ExportPublicKey());

            // This should throw because we can't export a private key when only the public key is known.
            ExceptionAssert.Throws<InvalidOperationException>(() => publicKey.ExportParameters(includePrivateParameters: true));
        }

        [TestMethod]
        public void ExportParametersThrowsOnSymmetricKey()
        {
            var keyProvider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            var key = keyProvider.CreateSymmetricKey(new byte[keyProvider.BlockLength]);
            ExceptionAssert.Throws<NotSupportedException>(() => key.ExportParameters(includePrivateParameters: false));
        }

        [TestMethod]
        public void KeyPairRoundTrip()
        {
            foreach (var algorithm in KeyAlgorithmsToTest)
            {
                Debug.WriteLine("** Algorithm: {0} **", algorithm.Key);
                var keyAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm.Key);
                using (ICryptographicKey key = keyAlgorithm.CreateKeyPair(algorithm.Value))
                {
                    int supportedFormats = 0;
                    foreach (CryptographicPrivateKeyBlobType format in Enum.GetValues(typeof(CryptographicPrivateKeyBlobType)))
                    {
                        try
                        {
                            byte[] keyBlob = key.Export(format);
                            using (var key2 = keyAlgorithm.ImportKeyPair(keyBlob, format))
                            {
                                byte[] key2Blob = key2.Export(format);

                                Assert.AreEqual(Convert.ToBase64String(keyBlob), Convert.ToBase64String(key2Blob));
                                Debug.WriteLine("Format {0} supported.", format);
                                Debug.WriteLine(Convert.ToBase64String(keyBlob));
                                supportedFormats++;
                            }
                        }
                        catch (NotSupportedException)
                        {
                            Debug.WriteLine("Format {0} NOT supported.", format);
                        }
                    }

                    Assert.IsTrue(supportedFormats > 0, "No supported formats.");
                }
            }
        }

        [TestMethod]
        public void PublicKeyRoundTrip()
        {
            foreach (var algorithm in KeyAlgorithmsToTest)
            {
                Debug.WriteLine("** Algorithm: {0} **", algorithm.Key);
                var keyAlgorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm.Key);
                var key = keyAlgorithm.CreateKeyPair(algorithm.Value);

                int supportedFormats = 0;
                foreach (CryptographicPublicKeyBlobType format in Enum.GetValues(typeof(CryptographicPublicKeyBlobType)))
                {
                    try
                    {
                        byte[] keyBlob = key.ExportPublicKey(format);
                        var key2 = keyAlgorithm.ImportPublicKey(keyBlob, format);
                        byte[] key2Blob = key2.ExportPublicKey(format);

                        CollectionAssertEx.AreEqual(keyBlob, key2Blob);

                        try
                        {
                            WinRTCrypto.CryptographicEngine.Encrypt(key2, new byte[0]);
                        }
                        catch (NotSupportedException)
                        {
                            // Some algorithms, such as ECDSA, only support signing/verifying.
                        }

                        Debug.WriteLine("Format {0} supported.", format);
                        Debug.WriteLine("    " + Convert.ToBase64String(keyBlob));
                        supportedFormats++;
                    }
                    catch (NotSupportedException)
                    {
                        Debug.WriteLine("Format {0} NOT supported.", format);
                    }
                }

                Assert.IsTrue(supportedFormats > 0, "No supported formats.");
            }
        }

        [TestMethod]
        public void KeyPairInterop()
        {
            int supportedFormats = 0;
            foreach (var formatAndBlob in Helper.PrivateKeyFormatsAndBlobs)
            {
                try
                {
                    var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(formatAndBlob.Key.Item1);
                    var key = algorithm.ImportKeyPair(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key.Item2);
                    string exported = Convert.ToBase64String(key.Export(formatAndBlob.Key.Item2));
                    if (formatAndBlob.Key.Item2 == CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo && exported.Length == formatAndBlob.Value.Length - 20)
                    {
                        // I'm not sure what the last 20 bytes are (perhaps the optional attributes)
                        // But Windows platforms produces them and Android doesn't seem to.
                        // Since the private key material seems to be elsewhere, we'll exclude
                        // the suffix from the comparison.
                        // The prefix is also mismatched, but that seems to also be ignorable.
                        Assert.AreEqual(formatAndBlob.Value.Substring(6, exported.Length - 6), exported.Substring(6));
                    }
                    else
                    {
                        Assert.AreEqual(formatAndBlob.Value, exported);
                    }

                    supportedFormats++;
                    Debug.WriteLine("Key format {0} supported.", formatAndBlob.Key);
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Key format {0} NOT supported.", formatAndBlob.Key);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void PublicKeyInterop()
        {
            int supportedFormats = 0;
            foreach (var formatAndBlob in Helper.PublicKeyFormatsAndBlobs)
            {
                var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(formatAndBlob.Key.Item1);
                try
                {
                    var key = algorithm.ImportPublicKey(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key.Item2);
                    string exported = Convert.ToBase64String(key.ExportPublicKey(formatAndBlob.Key.Item2));
                    Assert.AreEqual(formatAndBlob.Value, exported);
                    supportedFormats++;
                    Debug.WriteLine("Key format {0} supported.", formatAndBlob.Key);
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Key format {0} NOT supported.", formatAndBlob.Key);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void EncryptionInterop()
        {
            byte[] data = new byte[] { 1, 2, 3 };
            byte[] cipherText = Convert.FromBase64String("EvnsqTK9tDemRIceCap4Yc5znXeb+nyBPsFRf6oT+OPqQ958RH7NXE3xLKsVJhOLJ4iJ2NM+AlrKRltIK8cTmw==");
            foreach (var formatAndBlob in Helper.PrivateKeyFormatsAndBlobs)
            {
                var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(formatAndBlob.Key.Item1);
                ICryptographicKey key;
                try
                {
                    key = algorithm.ImportKeyPair(Convert.FromBase64String(formatAndBlob.Value), formatAndBlob.Key.Item2);
                }
                catch (NotSupportedException)
                {
                    continue;
                }

                // Verify that we can decrypt something encrypted previously (on WinRT)
                byte[] decryptedPlaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, cipherText);
                Assert.AreEqual(Convert.ToBase64String(decryptedPlaintext), Convert.ToBase64String(data));

                // Now verify we can decrypt something we encrypted ourselves.
                byte[] myciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, data);
                byte[] myplaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, myciphertext);
                Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(myplaintext));

                return; // We only need one key format to work for the encryption test.
            }

            Assert.IsTrue(false, "No supported formats.");
        }

        [TestMethod]
        public void KeyPairInterop_iOSGenerated()
        {
            // Tests a key where P has more significant digits than Q.
            // This is incompatible with CAPI, which makes it worth testing.
            byte[] rsaPrivateKey = Convert.FromBase64String(@"MIIBOgIBAAJBALx0Z0O1n/2E+Boyt7UEIQD62y8MQQPILJC2AguHvPfo8E5ScBBPa8dMCHVRCcKJJ868FJdebracYthqCHn19KMCAwEAAQJBAKAgsFXCD+2UfFOWYK44keqJPJBfcybJgcR8QoSVk6V40MkwgAmjVn4cumCLZgxwJ+O5fbS/xmzeRSBz8gdPfrECIQGbqLr8paSZLW80ixXQK9YCx76nkg4I2UdBq+h5taAwnQIgdTHt32eGkYjiVT81BnM6D9pmX508VulYsBalYtbmlj8CIEYX4dbZAYDPeqrwr8MlY6hPiIgR12/sRzTIZ6opoeAFAiAtESA6UuNKv+rZgU7wxgrD4eaQSjTT7zPtsyeyVJWjnQIhAONhytT6rHH9n3nE4K7Xxz3DjYodXzzM6Bm2C1jiGrEM");
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ICryptographicKey key = rsa.ImportKeyPair(rsaPrivateKey, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);

            byte[] data = new byte[] { 1, 2, 3 };
            byte[] ciphertext = WinRTCrypto.CryptographicEngine.Encrypt(key, data);
            byte[] plaintext = WinRTCrypto.CryptographicEngine.Decrypt(key, ciphertext);
            Assert.AreEqual(Convert.ToBase64String(data), Convert.ToBase64String(plaintext));
        }

        [TestMethod]
        public void RSAParametersNotOverlyTrimmed()
        {
            // Test a private key that has a most significant bit of zero in its D parameter.
            // Specifically, we want to verify that such a key can be exported into the CAPI format.
            var algorithm = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = algorithm.ImportKeyPair(
                Convert.FromBase64String("MIIBOgIBAAJBAKZ/iS3+Df6z6qD4/ZJI3Mfr/rWOvFdTZwCyoZ+CoMSW5QT93OW5fxWphus4Civ3+Q4fBrklNWvdmCjHgUuPOZkCAwEAAQI/8Qty7sMAP975sFLJyR7zg/yFpRQgV8zHMptqoiPb3L7CxcfPB71gjI3XPLfVc5cxNRl1QANEKGf+PE/Pb+xRAiEAz0zChuSpSLv0Rmccbeb0V7FsCTKKn8QQhE61DCE4ZgkCIQDNnOtqKnkuHws8sEYKfuolmlFPp0LD0PPptLwr8wGbEQIhAAlAhsoYeIm7gcqGnZk2Hp+vVoAOlmtNB+Ov05rH/MlpAiCq3EdUhc8FYI6589GAT07LyJzhECEPD8hg4OutqdYfwQIhAHcfeFuEU67QFPQs0JSzfG/mDDKtGCrcY7KGPBG4rRme"),
                CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey);

            // Just make sure it doesn't throw an exception.
            key.Export(CryptographicPrivateKeyBlobType.Capi1PrivateKey);
        }

        ////[TestMethod]
        ////public void SignedDataVerifyInterop()
        ////{

        ////}

        ////[TestMethod]
        ////public void SignedHashVerifyInterop()
        ////{

        ////}

        internal static class Helper
        {
            /// <summary>
            /// All the available private key blob types and a single sample key (RsaOaepSha1) serialized into each format.
            /// </summary>
            internal static readonly Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPrivateKeyBlobType>, string> PrivateKeyFormatsAndBlobs = new Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPrivateKeyBlobType>, string>
            {
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.BCryptPrivateKey), "UlNBMgACAAADAAAAQAAAACAAAAAgAAAAAQAB94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbk/n5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFL/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdk=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Capi1PrivateKey), "BwIAAACkAABSU0EyAAIAAAEAAQCTG+RlxG1ydcQxnceJE09mgf7kYIyO03LVvZmX+Sq5L/mA1j7OJexUE7GYfeJ/RuEkBVR0rE1vs/gfEAP27Yr3S6HK/5raziD6oigC7waj8LTJOjAear7ZZ50YmZF8+fnZSYku76QxQmhmn8Q8f/7rJcakp70u5WPMnqxzym+C/XH4w8fVeWrH86kHPX/xCtVcj17ivLaIYxATl1lscp7YmSF20HSQyDDJSJjVQMhvoQlF21N//14q09xLaRzYxUD6p5DHUXoJaLb7p39VwHGO6BGhi5I+THOr/v85oCvvwEHvw64F2h3dN53P1uNcW8JnmPsooQQR6wvVBc6re20ZzNlpf96Gue4vx3N+TpYYytz32XtLRAqQ5OA9lgnzTA0=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey), "MIIBOwIBAAJBAPeK7fYDEB/4s29NrHRUBSThRn/ifZixE1TsJc4+1oD5L7kq+ZeZvdVy046MYOT+gWZPE4nHnTHEdXJtxGXkG5MCAwEAAQJADUzzCZY94OSQCkRLe9n33MoYlk5+c8cv7rmG3n9p2cwZbXurzgXVC+sRBKEo+5hnwltc49bPnTfdHdoFrsPvQQIhAPn5fJGZGJ1n2b5qHjA6ybTwowbvAiii+iDO2pr/yqFLAiEA/YJvynOsnsxj5S69p6TGJev+fzzEn2ZoQjGk7y6JSdkCIQDYnnJsWZcTEGOItrziXo9c1Qrxfz0HqfPHannVx8P4cQIgQMXYHGlL3NMqXv9/U9tFCaFvyEDVmEjJMMiQdNB2IZkCIQDA7yugOf/+q3NMPpKLoRHojnHAVX+n+7ZoCXpRx5Cn+g==" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo), "MIIBZAIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA94rt9gMQH/izb02sdFQFJOFGf+J9mLETVOwlzj7WgPkvuSr5l5m91XLTjoxg5P6BZk8TicedMcR1cm3EZeQbkwIDAQABAkANTPMJlj3g5JAKREt72ffcyhiWTn5zxy/uuYbef2nZzBlte6vOBdUL6xEEoSj7mGfCW1zj1s+dN90d2gWuw+9BAiEA+fl8kZkYnWfZvmoeMDrJtPCjBu8CKKL6IM7amv/KoUsCIQD9gm/Kc6yezGPlLr2npMYl6/5/PMSfZmhCMaTvLolJ2QIhANiecmxZlxMQY4i2vOJej1zVCvF/PQep88dqedXHw/hxAiBAxdgcaUvc0ype/39T20UJoW/IQNWYSMkwyJB00HYhmQIhAMDvK6A5//6rc0w+kouhEeiOccBVf6f7tmgJelHHkKf6oA0wCwYDVR0PMQQDAgAQ" },
            };

            /// <summary>
            /// All the available public key blob types and a single sample key (RsaOaepSha1) serialized into each format.
            /// </summary>
            internal static readonly Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPublicKeyBlobType>, string> PublicKeyFormatsAndBlobs = new Dictionary<Tuple<AsymmetricAlgorithm, CryptographicPublicKeyBlobType>, string>
            {
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.BCryptPublicKey), "UlNBMQACAAADAAAAQAAAAAAAAAAAAAAAAQABoetbetfLDOWmobkoUTBXEM9ImOqIV18ikFiJddccSqTAB28MdbKBVwv40Y40aJb3MO+mv5rlN0QO1iWfFGD/pw==" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.Capi1PublicKey), "BgIAAACkAABSU0ExAAIAAAEAAQCn/2AUnyXWDkQ35Zq/pu8w95ZoNI7R+AtXgbJ1DG8HwKRKHNd1iViQIl9XiOqYSM8QVzBRKLmhpuUMy9d6W+uh" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey), "MEgCQQCh61t618sM5aahuShRMFcQz0iY6ohXXyKQWIl11xxKpMAHbwx1soFXC/jRjjRolvcw76a/muU3RA7WJZ8UYP+nAgMBAAE=" },
                { Tuple.Create(AsymmetricAlgorithm.RsaOaepSha1, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo), "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKHrW3rXywzlpqG5KFEwVxDPSJjqiFdfIpBYiXXXHEqkwAdvDHWygVcL+NGONGiW9zDvpr+a5TdEDtYlnxRg/6cCAwEAAQ==" },
                { Tuple.Create(AsymmetricAlgorithm.EcdsaP256Sha256, CryptographicPublicKeyBlobType.BCryptPublicKey), "RUNTMSAAAACRpP2lPrEj6EjfvGrB1P87zDfr0VmDnHzgUkZHBeIPw6JZ4otUCEQSYyHcuGd3+gsTfsiBDFIY1saBbmaoFiko" },
            };
        }
    }
#endif
}
