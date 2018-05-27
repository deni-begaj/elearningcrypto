using ELearningCryptography.Encryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;

namespace ELearningCryptography.Controllers
{
    public class LiveTestController : Controller
    {
        #region Views 

        public ActionResult Index()
        {
            return View();
        }
        public ActionResult Aes()
        {
            return View();
        }

        public ActionResult Des()
        {
            return View();
        }


        public ActionResult Md5()
        {
            return View();
        }

        public ActionResult Sha1()
        {
            return View();
        }

        public ActionResult Sha2()
        {
            return View();
        }

        public ActionResult Sha3()
        {
            return View();
        }

        public ActionResult Rsa()
        {
            return View();
        }

        public ActionResult DiffieHellman()
        {
            return View();
        }

        #endregion

        #region Methods

        #region Aes

        public string AesEncrypt(string value, string password)
        {
            string encrypted = Cryptography.Aes.Encrypt(value, password);
            return encrypted;
        }

        public string AesDecrypt(string value, string password)
        {
            string decrypted = Cryptography.Aes.Decrypt(value, password);
            return decrypted;
        }

        #endregion

        #region Des

        public string DesEncrypt(string value)
        {
            string encrypted = Cryptography.Des.Encrypt(value);
            return encrypted;
        }

        public string DesDecrypt(string value)
        {
            string decrypted = Cryptography.Des.Decrypt(value);
            return decrypted;
        }

        #endregion

        #region Rsa

        public string RsaEncrypt(string value, int keySize)
        {
            string encrypted = Cryptography.Rsa.Encrypt(value, keySize);
            return encrypted;
        }

        [HttpPost]
        public string RsaDecrypt(RsaModel obj)
        {
            string decrypted = Cryptography.Rsa.Decrypt(obj.value, obj.keySize);
            return decrypted;
        }

        public class RsaModel
        {
            public string value { get; set; }
            public int keySize { get; set; }

        }

        #endregion

        #region Md5

        public string Md5Hash(string value)
        {
            string hash = Cryptography.Md5.Hash(value);
            return hash;
        }

        public async Task<string> Md5Reverse(string value)
        {
            string reversed = await Cryptography.Md5.ReverseMd5(value);
            return reversed;
        }

            #endregion

        #region Sha

        public string Sha1Hash(string value)
        {
            string hash = Cryptography.Sha1.Hash(value);
            return hash;
        }

        public string Sha2Hash(string value, string keySize)
        {
            string hash = Cryptography.Sha2.Hash(value, keySize);
            return hash;
        }

        public string Sha3Hash(string value)
        {
            string hash = Cryptography.Sha3.Hash(value);
            return hash;
        }

        #endregion

        #region DiffieHellman

        public ActionResult DiffieHellmanEncrypt(string value)
        {
            var a = new Cryptography.DiffieHellman();
            var b = new Cryptography.DiffieHellman();

            string enc = a.Encrypt(b.PublicKey, value);
            string desc = b.Decrypt(a.PublicKey, enc, a.IV);
            var arr = new List<string> { enc, desc };
            return Json(arr, JsonRequestBehavior.AllowGet);
        }
        
        #endregion

        #endregion

    }
}