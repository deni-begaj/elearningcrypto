using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ELearningCryptography.Controllers
{
    public class HashFunctionsController : Controller
    {
        // GET: HashFunctions
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Md5()
        {
            return View();
        }

        public ActionResult Sha()
        {
            return View();
        }

    }
}