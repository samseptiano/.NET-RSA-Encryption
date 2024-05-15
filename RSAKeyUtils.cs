using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;

namespace TNSDS.SFAService.Common
{
    public class RSAKeyUtils
    {
        public static RSAParameters LoadPrivateKey(string privateKeyPath)
        {
            try
            {
                using (TextReader privateKeyTextReader = File.OpenText(privateKeyPath))
                {
                    var pemReader = new PemReader(privateKeyTextReader);
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                    RsaPrivateCrtKeyParameters rsaParameters = (RsaPrivateCrtKeyParameters)keyPair.Private;

                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(rsaParameters);
                    return rsaParams;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading private key: {ex.Message}");
                throw;
            }
        }

        public static RSAParameters LoadPublicKey(string publicKeyPath)
        {
            try
            {
                using (TextReader publicKeyTextReader = File.OpenText(publicKeyPath))
                {
                    var pemReader = new PemReader(publicKeyTextReader);
                    RsaKeyParameters rsaParameters = (RsaKeyParameters)pemReader.ReadObject();

                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(rsaParameters);
                    return rsaParams;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading public key: {ex.Message}");
                throw;
            }

        }
       }
    }