using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static RSAKeyPair.RSAKeys;

namespace RSAKeyPair
{
    class Program
    {
        static void Main(string[] args)
        {

            //Call GenerateRSAKeyPair here
            //Use ur secret Key from the call above and call HmacSha256WithKey passing the secreat key above and message in the right format



        }

        public static string GenerateRSAKeyPair()
        {
            try
            {
                RSAKeys rsa = new RSAKeys();
                AsymmetricCipherKeyPair keypair = null;
                using (RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(1024))
                {
                    RSAParameters rsaKeyInfo = rsaProvider.ExportParameters(true);
                    keypair = DotNetUtilities.GetRsaKeyPair(rsaKeyInfo);
                }

                var _privateKey = rsa.ImportPrivateKey(keypair);
                var _publicKey = rsa.ImportPublicKey(keypair);

                Keys keys = new Keys();

                keys.privateKey = rsa.ExportPrivateKey(_privateKey);
                keys.publicKey = rsa.ExportPublicKey(_publicKey);

                //call Arca and get response then 
                //Decrypt here

                ArcaRequest arca = new ArcaRequest();
                //ArcaResult readTask = null;
                System.Threading.Tasks.Task<ArcaResult> readTask = null;
                arca.svaCode = "TESTCode";
                arca.rsaPublicKey = keys.publicKey;

                HttpClient client = new HttpClient();
                client.BaseAddress = new Uri("");
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(
                    new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("key", "testKeyValue");
                var response = client.PostAsJsonAsync("", arca);
                response.Wait();
                if (response.Result.IsSuccessStatusCode)
                {

                    readTask = response.Result.Content.ReadAsAsync<ArcaResult>();
                    readTask.Wait();


                }

                return rsa.RsaDecryptWithPrivate(readTask.Result.key, keypair);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public static HmacSha256WithKeyResponse HmacSha256WithKey(string message, string secret)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
                string _message = message + timestamp.ToString();
                Encoding ascii = Encoding.ASCII;
                HMACSHA256 hmac = new HMACSHA256(ascii.GetBytes(secret));
                var signaure = Convert.ToBase64String(hmac.ComputeHash(ascii.GetBytes(_message)));
                HmacSha256WithKeyResponse resp = new HmacSha256WithKeyResponse();

                resp.signature = signaure;
                resp.time = timestamp;
                return resp;
            }
            catch (Exception ex)
            {
                return null;
            }

        }

    }
}
