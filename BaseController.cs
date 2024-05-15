using System;
using System.Collections.Generic;
using System.IO;
using Ionic.Zip;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Http;
using System.Threading.Tasks;
using System.IO.Compression;

using TNSDS.Dao.Base;
using TNSDS.Dto.Base;
using TNSDS.Dao.Entity;
using TNSDS.Dao.General;
using TNSDS.Dto.General;
using TNSDS.Dao.Sales;
using TNSDS.Dto.Sales;
using TNSDS.Dao.SFA;
using TNSDS.Dto.SFA;
using TNSDS.Dao.Zystem;
using TNSDS.Dto.Zystem;
using TNSDS.Dao.Inventory;
using TNSDS.Dto.Inventory;

using TNSDS.SFAService.Common;
using TNSDS.SFAService.Model;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using ZipFile = Ionic.Zip.ZipFile;
using SelectPdf;

namespace TNSDS.SFAService.Controllers.Base
{
    public class BaseController : ApiController
    {

        public BaseController(){}


        [HttpPost]
        [Route("api/Base/RSA/encrypt")]
        public RSAEncryptionResponse<String> encryptRSA([FromBody] RSAEncryptionRequest request)
        {
            Encryption encObj = new Encryption();
            RSAEncryptionResponse<String> res = new RSAEncryptionResponse<String>();

            if ((request.NEEMNO != null && request.NEEMNO != String.Empty) && (request.NEPSWD != null && request.NEPSWD != String.Empty))
            {
                NSSRDao dao = new NSSRDao();
                NSSRDto dto = new NSSRDto();

                dto.NDEMNO = request.NEEMNO;
                dto.NDPSWD = encObj.Encrypt(request.NEPSWD);
                dto.NDCONO = "";
                dto.NDBRNO = "";
                NSSRDto resultDto = dao.GetWithNEPSWD(dto);

                if (resultDto == null)
                {
                    res.data = null;
                    res.message = "employee id and/or password is wrong";
                    res.response_code = 401;
                    res.error_code = "ERR_UNAUTHORIZE";
                    return res;
                }
                else {
                    if (resultDto.NDEMNO == null || resultDto.NDEMNO == String.Empty)
                    {
                        res.data = null;
                        res.message = "employee id and/or password is wrong";
                        res.response_code = 401;
                        res.error_code = "ERR_UNAUTHORIZE";
                        return res;
                    }
                }


                try
                {
                    string rsakeyPath = HttpContext.Current.Request.MapPath(@"~\Assets\");
                    RSAParameters publicKey = RSAKeyUtils.LoadPublicKey(rsakeyPath + "rsa_public_key.pem");

                    using (RSA rsa = RSA.Create())
                    {
                        rsa.ImportParameters(publicKey);

                        byte[] dataBytes = Encoding.UTF8.GetBytes(request.data);
                        byte[] encryptedBytes = rsa.Encrypt(dataBytes, RSAEncryptionPadding.Pkcs1);

                        string encryptedData = Convert.ToBase64String(encryptedBytes);

                        res.data = encryptedData;
                        res.message = "success";
                        res.response_code = 200;
                        res.error_code = "";

                        return res;
                    }
                }
                catch (Exception ex)
                {
                    res.data = null;
                    res.message = ex.Message;
                    res.response_code = 500;
                    res.error_code = "ERR_EXCEPTION";
                    return res;
                }
            }
            else {
                res.data = null;
                res.message = "employee id and/or password is wrong";
                res.response_code = 401;
                res.error_code = "ERR_UNAUTHORIZE";
                return res;
            }

        }

        [HttpPost]
        [Route("api/Base/RSA/decrypt")]
        public RSAEncryptionResponse<String> decryptRSA([FromBody] RSAEncryptionRequest request)
        {

            RSAEncryptionResponse<String> res = new RSAEncryptionResponse<String>();

            try
            {
                // Replace with the actual path to your private key file
                string rsakeyPath = HttpContext.Current.Request.MapPath(@"~\Assets\");

                string privateKeyFilePath = Path.Combine(rsakeyPath, "rsa_private_key.pem");

                string privateKey;
                using (StreamReader reader = System.IO.File.OpenText(privateKeyFilePath))
                {
                    privateKey = reader.ReadToEnd();
                }

                TextReader textReader = new StringReader(privateKey);
                PemReader pemReader = new PemReader(textReader);
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(privateKeyParams);
                    rsa.ImportParameters(rsaParams);

                    // Decode the base64-encoded encrypted data
                    byte[] encryptedBytes = Convert.FromBase64String(request.data);

                    // Decrypt the data
                    byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

                    // Convert the decrypted bytes to a string
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

                    res.data = decryptedText;
                    res.message = "success";
                    res.response_code = 200;
                    res.error_code = "";

                    return res;
                }
            }
            catch (Exception ex)
            {
                res.data = null;
                res.message = ex.Message;
                res.response_code = 500;
                res.error_code = "ERR_EXCEPTION";
                return res;
            }

        }


    }
}
