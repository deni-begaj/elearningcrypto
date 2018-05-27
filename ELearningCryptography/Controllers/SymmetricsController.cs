using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ELearningCryptography.Controllers
{
    public class SymmetricsController : Controller
    {
        // GET: Symetrics
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

        public ActionResult BlowFish()
        {
            return View();
        }
    }
}