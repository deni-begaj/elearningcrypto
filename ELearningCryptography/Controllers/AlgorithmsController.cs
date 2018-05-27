using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ELearningCryptography.Controllers
{
    public class AlgorithmsController : Controller
    {
        // GET: Algorithms
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult History()
        {
            return View();
        }
    }
}