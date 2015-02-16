/*
 * [File]
 * crifanLibAmazon.cs
 * 
 * [Function]
 * Crifan Lib of C# version for Amazon
 * 
 * [Note]
 * 1.use crifanLib.cs
 * http://www.crifan.com/crifan_released_all/crifanlib/
 * http://www.crifan.com/crifan_csharp_lib_crifanlib_cs/
 * 2.use HtmlAgilityPack
 *  
 * [Version]
 * v3.0
 * 
 * [update]
 * 2013-09-10
 * 
 * [Author]
 * Crifan Li
 * 
 * [Contact]
 * http://www.crifan.com/contact_me/
 * 
 * [History]
 * [v3.0]
 * 1. update many function to extract infos
 * 
 * [v2.6]
 * 1. update many functions
 * 
 * [v2.5]
 * 1. add NLog log system support
 * 
 * [v2.4]
 * 1. update checkVariation, extractSearchItemList
 * 2. add extractProductKeywordField
 * 
 * [v2.1]
 * 1. checkVariation, extractAsinFromProductUrl, generateProductUrlFromAsin
 * 2. update some func
 * 
 * [v1.7]
 * 1. add extractSinglePageSellerInfo, extractAllSingleTypeSellerInfo, extractAllSellerInfo
 * 2. add extractProductReviewNumber, extractProductBestSellerRankList
 * 
 * [v1.2]
 * 1. add extractProductWeight, extractProductDimension
 * 
 * [v1.0]
 * 1. initial added 
 * extractMainCategoryList
 * extractNextPageUrl
 * extractProductTitle
 * extractProductBulletList
 * extractProductDescription
 * extractProductImageList
 */

using System;
using System.Collections.Generic;
using System.Text;

using System.Text.RegularExpressions;

using System.Web;
using HtmlAgilityPack;

using NLog;
using NLog.Targets;
using NLog.Config;

public class crifanLibAmazon
{
    public static string constAmazonDomainUrl = "http://www.amazon.com";
    public static string constAmazonGpProductUrl = "http://www.amazon.com/gp/product/";
    public static string constAmazonGpOfferListingUrl = "http://www.amazon.com/gp/offer-listing/";
    public static string constAmazonGpCustomImageUrl = "http://www.amazon.com/gp/customer-media/product-gallery/";
    
    public crifanLib crl;

    //for log
    public Logger gLogger = null;


    //for main catetory/best seller category/...
    public struct categoryItem
    {
        public string Name { get; set; } //Amazon Instant Video
        public string Url { get; set; } //http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dinstant-video
        //for main category, category key called search alias
        public string Key { get; set; } //instant-video
    };

    public struct productDimension
    {
        public float length;
        public float width;
        public float height;
    };

    public struct productSellerInfo
    {
        public string name;
        public float price; //dolloar
        //public string condition;
        //public string rating;
        //...
    };

    public struct categoryInfo
    {
        public string name; //category name
        public string link; //category link
    }

    public struct productBestRank
    {
        public int rankNumber;
        public List<categoryInfo> categoryList;
    };

    public struct searchResultItem
    {
        public string productUrl;
        //add more if need
    }

    public struct variationItem
    {
        public string label;
        public string url;
    }

    public struct productVariationInfo
    {
        public int curSelectdIdx;
        public string curSelectLable;
        public string curSelectUrl;

        public List<variationItem> variationList;
    }

    //find global defaut (current using) logger
    public crifanLibAmazon()
    {
        //!!! for load embedded dll: (1) register resovle handler
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

        //init something
        crl = new crifanLib();

        gLogger = LogManager.GetLogger("");
    }

    //specify your logger
    public crifanLibAmazon(Logger logger)
    {
        //!!! for load embedded dll: (1) register resovle handler
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

        //init something
        crl = new crifanLib();

        gLogger = logger;
    }


    //!!! for load embedded dll: (2) implement this handler
    System.Reflection.Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
    {
        string dllName = args.Name.Contains(",") ? args.Name.Substring(0, args.Name.IndexOf(',')) : args.Name.Replace(".dll", "");

        dllName = dllName.Replace(".", "_");

        if (dllName.EndsWith("_resources")) return null;

        System.Resources.ResourceManager rm = new System.Resources.ResourceManager(GetType().Namespace + ".Properties.Resources", System.Reflection.Assembly.GetExecutingAssembly());

        byte[] bytes = (byte[])rm.GetObject(dllName);

        return System.Reflection.Assembly.Load(bytes);
    }

    
    /*
     * [Function]
     * extract product asin from product url
     * [Input]
     * amazon product url
     * eg:
     * http://www.amazon.com/gp/product/B0083PWAPW
     * http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1370574186&sr=1-4
     * http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_1?ie=UTF8&qid=1369818181&sr=1-1
     * http://www.amazon.com/gp/product/B003BIG0DO/ref=twister_B000AST3AK?ie=UTF8&psc=1
     * [Output]
     * product asin
     * eg:
     * B0083PWAPW
     * B000AST3AK
     * B007OZNZG0
     * B003BIG0DO
     * [Note]
     */
    public bool extractAsinFromProductUrl(string productUrl, out string itemAsin)
    {
        bool foundAsin = false;
        itemAsin = "";

        if (!foundAsin)
        {
            if(crl.extractSingleStr(@"^http://www\.amazon\.com/gp/product/([a-zA-Z\d]+)(/.+)?$",productUrl, out itemAsin,RegexOptions.IgnoreCase))
            {
                foundAsin = true;
            }
        }

        if (!foundAsin)
        {
            if (crl.extractSingleStr(@"^http://www\.amazon\.com/.+?/dp/([a-zA-Z\d]+)(/.+?)$", productUrl, out itemAsin, RegexOptions.IgnoreCase))
            {
                foundAsin = true;
            }
        }

        return foundAsin;
    }

    /*
     * [Function]
     * generate product url from asin
     * [Input]
     * amazon product asin
     * eg:
     * B0083PWAPW
     * [Output]
     * whole product url
     * eg:
     * http://www.amazon.com/gp/product/B0083PWAPW
     * [Note]
     */
    public string generateProductUrlFromAsin(string itemAsin)
    {
        string productUrl = "";
        //http://www.amazon.com/gp/product/B0057FQCNC
        //http://www.amazon.com/gp/product/B0083PWAPW
        productUrl = constAmazonGpProductUrl + itemAsin; //http://www.amazon.com/gp/product/B0083PWAPW

        return productUrl;
    }
    
    /*
     * [Function]
     * generate offer listing url from asin
     * [Input]
     * amazon item asin
     * eg:
     * B003F4TH6G
     * [Output]
     * offer listing url
     * eg:
     * http://www.amazon.com/gp/offer-listing/B003F4TH6G
     * [Note]
     */
    public string generateOfferListingUrl(string itemAsin)
    {
        string offerListingUrl = "";
        //http://www.amazon.com/gp/offer-listing/B003F4TH6G
        offerListingUrl = constAmazonGpOfferListingUrl + itemAsin; //http://www.amazon.com/gp/offer-listing/B003F4TH6G

        return offerListingUrl;
    }

    /*
     * [Function]
     * generate custom image url from asin
     * [Input]
     * amazon item asin
     * eg:
     * B003C9HUDQ
     * [Output]
     * custom image url
     * eg:
     * http://www.amazon.com/gp/customer-media/product-gallery/B003C9HUDQ
     * [Note]
     */
    public string generateCustomImageUrlFromAsin(string itemAsin)
    {
        string customImageUrl = "";
        //http://www.amazon.com/gp/customer-media/product-gallery/B003C9HUDQ
        customImageUrl = constAmazonGpCustomImageUrl + itemAsin;

        return customImageUrl;
    }
    
    /*
     * [Function]
     * extract next page url
     * [Input]
     * current page url or its html
     * http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dinstant-video
     * [Output]
     * http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Dinstant-video#/ref=sr_pg_2?rh=n%3A2858778011&page=2&ie=UTF8&qid=1368688123
     * [Note]
     */
    public bool extractNextPageUrl(string curPageUrl, string curPageHtml, out string nextPageUrl)
    {
        bool gotNextPageUrl = false;
        nextPageUrl = "";

        //if no give html, then get it first
        if (string.IsNullOrEmpty(curPageHtml))
        {
            curPageHtml = crl.getUrlRespHtml_multiTry(curPageUrl);
        }

        /*
            <a title="Next Page" 
                        id="pagnNextLink" 
                        class="pagnNext" 
                        href="/s/ref=sr_pg_2?rh=n%3A2858778011&amp;page=2&amp;ie=UTF8&amp;qid=1368696683">
                        <span id="pagnNextString">Next Page</span>
                        <span class="srSprite pagnNextArrow"></span>
                        </a>
            */
        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(curPageHtml);
        HtmlNode nextPageNode = htmlDoc.DocumentNode.SelectSingleNode("//a[@id='pagnNextLink']");
        if (nextPageNode != null)
        {
            string hrefValue = nextPageNode.Attributes["href"].Value;//"/s/ref=sr_pg_2?rh=n%3A2625373011%2Cn%3A%212644981011%2Cn%3A%212644982011%2Cn%3A2858778011&amp;page=2&amp;ie=UTF8&amp;qid=1368697688"
            nextPageUrl = constAmazonDomainUrl + HttpUtility.HtmlDecode(hrefValue); //"http://www.amazon.com/s/ref=sr_pg_2?rh=n%3A2625373011%2Cn%3A%212644981011%2Cn%3A%212644982011%2Cn%3A2858778011&page=2&ie=UTF8&qid=1368697688"

            gotNextPageUrl = true;
        }
        else
        {
            gotNextPageUrl = false;
            gLogger.Debug("can not find pagnNextLink for " + curPageUrl);
        }

        return gotNextPageUrl;
    }

    /*
     * [Function]
     * extract searched item list from amazon search result html 
     * [Input]
     * amazon search result url or its html
     * [Output]
     * searched item list, each type is searchResultItem
     * [Note]
     */
    public bool extractSearchItemList(string searchUrl, string searchRespHtml, out List<searchResultItem> itemList)
    {
        bool extractItemListOk = false;
        itemList = new List<searchResultItem>();

        //if no give html, then get it first
        if (string.IsNullOrEmpty(searchRespHtml))
        {
            searchRespHtml = crl.getUrlRespHtml_multiTry(searchUrl);
        }

        //type1:
        //<div id="atfResults" class="list results twister">
        //<div id="result_0" class="result firstRow product celwidget" name="B00CE18P0K">
        //<div id="result_1" class="result product celwidget" name="B00CL68QVQ">
        //<div id="result_2" class="result lastRow product celwidget" name="B008Y7N7JW">

        //<div id="btfResults" class="list results twister">
        //<div id="result_3" class="result product celwidget" name="B008XKSW7M">
        //...

        //type2:
        //<div id="result_24" class="fstRowGrid prod celwidget" name="B00CDURMD8">
        //<div id="result_25" class="fstRowGrid prod celwidget" name="B003AZBASI">
        //...


        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(searchRespHtml);
        HtmlNodeCollection resultItemNodeList;
        //resultItemNodeList = htmlDoc.DocumentNode.SelectNodes("//div[@id and @class and @name]");
        //resultItemNodeList = htmlDoc.DocumentNode.SelectNodes("//div[starts-with(@id, 'result_') and starts-with(@class, 'result ') and @name]");
        resultItemNodeList = htmlDoc.DocumentNode.SelectNodes("//div[starts-with(@id, 'result_') and @class and @name]");

        
        //============ for Best Seller ===========
        //http://www.amazon.com/Best-Sellers-Appliances/zgbs/appliances/ref=zg_bs_nav_0
        //<div class="zg_itemImmersion">
        HtmlNodeCollection bestSellerResultItemNodeList = htmlDoc.DocumentNode.SelectNodes("//div[@class='zg_itemImmersion']");


        //============ for some main category ===========
        //http://www.amazon.com/s/ref=sr_nr_n_0?rh=n%3A2858778011%2Cn%3A2858905011&bbn=2858778011&ie=UTF8&qid=1371204088&rnid=2858778011
        //<div id="mainResults" class="results ilr2">
        //    <ul class="ilo2">
        //    <li id="result_0" class="ilo2" name="B00D6C5RMA">
        //      ......
        //    </li>
        //    <li id="result_1" class="ilo2" name="B008Y7N7JW">
        //      ......
        //    </li>
        HtmlNodeCollection mainResultsLiNodeList = htmlDoc.DocumentNode.SelectNodes("//li[starts-with(@id, 'result_') and @class and @name]");


        if (resultItemNodeList != null)
        {
            foreach (HtmlNode resultItemNode in resultItemNodeList)
            {
                crifanLibAmazon.searchResultItem curItem = new crifanLibAmazon.searchResultItem();
                //<h3 class="title"  ><a class="title" href="http://www.amazon.com/Pilot-HD/dp/B00CE18P0K/ref=sr_1_1?s=instant-video&amp;ie=UTF8&amp;qid=1368685217&amp;sr=1-1">Zombieland Season 1 [HD]</a> <span class="starring">Starring Kirk Ward,&#32;Tyler Ross,&#32;Maiara Walsh and Izabela Vidovic</span></h3>
                //<h3 class="newaps">    <a href="http://www.amazon.com/Pilot-HD/dp/B00CE18P0K/ref=sr_1_1?s=instant-video&amp;ie=UTF8&amp;qid=1369302177&amp;sr=1-1"><span class="lrg bold">Zombieland Season 1 [HD]</span></a> <span class="med reg"><span class="starring">Starring Kirk Ward,&#32;Tyler Ross,&#32;Maiara Walsh and Izabela Vidovic</span></span>    </h3>
                //HtmlNode h3aNode = resultItemNode.SelectSingleNode(".//h3[@class='title']/a");
                HtmlNode h3aNode = resultItemNode.SelectSingleNode(".//h3[@class]/a");
                if (h3aNode != null)
                {
                    string productUrl = h3aNode.Attributes["href"].Value;//"http://www.amazon.com/Pilot-HD/dp/B00CE18P0K/ref=sr_1_1?s=instant-video&amp;ie=UTF8&amp;qid=1368688342&amp;sr=1-1"
                    string decodedProductUrl = HttpUtility.HtmlDecode(productUrl);//"http://www.amazon.com/Silver-Linings-Playbook/dp/B00CL68QVQ/ref=sr_1_2?s=instant-video&ie=UTF8&qid=1368688342&sr=1-2"

                    curItem.productUrl = decodedProductUrl;

                    itemList.Add(curItem);

                    extractItemListOk = true;
                }
                else
                {
                    //something wrong
                    gLogger.Debug("can not find h3[@class]/a within resultItemNode for " + searchUrl);
                }
            }
        }
        else if ((bestSellerResultItemNodeList != null) && (bestSellerResultItemNodeList.Count > 0))
        {
            foreach (HtmlNode resultItemNode in bestSellerResultItemNodeList)
            {
                crifanLibAmazon.searchResultItem curItem = new crifanLibAmazon.searchResultItem();
                //<div class="zg_itemImmersion">
                //    <div class="zg_rankDiv"><span class="zg_rankNumber">1.</span></div>
                //    <div class="zg_itemWrapper" style="height:285px">
                //        <div class="zg_image">
                //            <div class="zg_itemImageImmersion">
                //                <a  href="http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=zg_bs_appliances_1">
                //                    <img src="http://ecx.images-amazon.com/images/I/31hHFppUjnL._SL160_SL150_.jpg" alt="GE MWF Refrigerator Water Filter, 1-Pack" title="GE MWF Refrigerator Water Filter, 1-Pack" onload="if (typeof uet == 'function') { uet('af'); }"/>
                //                </a>
                //            </div>
                //        </div>
                HtmlNode zgItemNode = resultItemNode.SelectSingleNode(".//div[@class='zg_itemImageImmersion']/a");
                if (zgItemNode != null)
                {
                    string productUrl = zgItemNode.Attributes["href"].Value;//"\n\n\n\n\n\n\nhttp://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=zg_bs_appliances_1/184-1909798-9660844\n"
                    productUrl = productUrl.Trim(); //"http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=zg_bs_appliances_1/184-1909798-9660844"
                    string decodedProductUrl = HttpUtility.HtmlDecode(productUrl);//"http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=zg_bs_appliances_1/184-1909798-9660844"

                    curItem.productUrl = decodedProductUrl;

                    itemList.Add(curItem);

                    extractItemListOk = true;
                }
                else
                {
                    //something wrong
                    gLogger.Debug("can not find zg_itemImageImmersion within resultItemNode for " + searchUrl);
                }
            }
        }
        else if ((mainResultsLiNodeList != null) && (mainResultsLiNodeList.Count > 0))
        {
            foreach (HtmlNode mainResultsLiNode in mainResultsLiNodeList)
            {
                crifanLibAmazon.searchResultItem curItem = new crifanLibAmazon.searchResultItem();

                //<a class="ilo2 ilc2" href="http://www.amazon.com/Identity-Thief/dp/B00D6C5RMA/ref=lp_2858905011_1_1?ie=UTF8&amp;qid=1371204118&amp;sr=1-1">
                //  <img src="http://ecx.images-amazon.com/images/I/515k2ziGvrL._AA200_.jpg" class="ilo2 ilc2" />
                //</a>
                HtmlNode ilo2Node = mainResultsLiNode.SelectSingleNode(".//a[@class='ilo2 ilc2']");
                if (ilo2Node != null)
                {
                    string productUrl = ilo2Node.Attributes["href"].Value; //"http://www.amazon.com/Identity-Thief/dp/B00D6C5RMA/ref=lp_2858905011_1_1?ie=UTF8&amp;qid=1371204140&amp;sr=1-1"
                    productUrl = productUrl.Trim(); //"http://www.amazon.com/Identity-Thief/dp/B00D6C5RMA/ref=lp_2858905011_1_1?ie=UTF8&amp;qid=1371204140&amp;sr=1-1"
                    string decodedProductUrl = HttpUtility.HtmlDecode(productUrl); //"http://www.amazon.com/Identity-Thief/dp/B00D6C5RMA/ref=lp_2858905011_1_1?ie=UTF8&qid=1371204140&sr=1-1"

                    curItem.productUrl = decodedProductUrl;

                    itemList.Add(curItem);

                    extractItemListOk = true;
                }
                else
                {
                    //something wrong
                    gLogger.Debug("can not find ilo2 ilc2 within mainResultsLiNode for " + searchUrl);
                }
            }
        }
        else
        {
            //something wrong
            gLogger.Debug("not find any kind of result item for " + searchUrl);
        }

        return extractItemListOk;
    }

    /*
     * [Function]
     * extract variation info from product url
     * [Input]
     * amazon product url
     * eg:
     * http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1370574186&sr=1-4
     * http://www.amazon.com/gp/product/B003BIG0DO/ref=twister_B000AST3AK?ie=UTF8&psc=1
     * [Output]
     * variation info
     * [Note]
     */
    public bool checkVariation(string productUrl, out productVariationInfo variationInfo)
    {
        //init
        bool foundVariation = false;
        variationInfo = new productVariationInfo();
        variationInfo.variationList = new List<variationItem>();
        variationInfo.curSelectdIdx = -1;
        variationInfo.curSelectUrl = productUrl;

        string extractedAsin = "";
        if (extractAsinFromProductUrl(productUrl, out extractedAsin))
        {

        }
        else
        {
            //something wrong
            gLogger.Warn("can not extract asin from url=" + productUrl);
        }

        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1370574186&sr=1-4
        //has 4 variation
         //<div id=selected_size_name class="variationSelected">
         //   <b class="variationDefault">Size:  </b>
         //   <b class="variationLabel">1-Pack</b>
         //</div>
 
         //<div class="clearfix spacediv"> 

         //   <div title="Click to select  1-Pack" tabindex="0" class="swatchOuter" count=0 key=size_name >
         //       <div id="size_name_0" class=swatchSelect >
         //       <div class="swatchTextBgClass">
         //         <div class="swatchInnerText">1-Pack</div>
         //       </div>
         //       <div class="selectedArrow"></div>
         //   </div>
         //   </div>

         //   <div title="Click to select  2-Pack" tabindex="0" class="swatchOuter" count=1 key=size_name >
         //       <a href="http://www.amazon.com/gp/product/B003BIG0DO/ref=twister_B000AST3AK?ie=UTF8&psc=1">
         //       <div id="size_name_1" class=swatchAvailable >
         //       <div class="swatchTextBgClass">
         //         <div class="swatchInnerText">2-Pack</div>
         //       </div>
         //       <div class="selectedArrow"></div>
         //   </div>
         //           </a>
         //   </div>

         //   <div title="Click to select  3 Pack" tabindex="0" class="swatchOuter" count=2 key=size_name >
         //       <a href="http://www.amazon.com/gp/product/B00149JVOC/ref=twister_B000AST3AK?ie=UTF8&psc=1">
         //       <div id="size_name_2" class=swatchAvailable >
         //       <div class="swatchTextBgClass">
         //         <div class="swatchInnerText">3 Pack</div>
         //       </div>
         //       <div class="selectedArrow"></div>
         //   </div>
         //           </a>
         //   </div>
    
         //   <div title="Click to select  4-Pack" tabindex="0" class="swatchOuter" count=3 key=size_name >
         //       <a href="http://www.amazon.com/gp/product/B003BIG0DY/ref=twister_B000AST3AK?ie=UTF8&psc=1">
         //       <div id="size_name_3" class=swatchAvailable >
         //       <div class="swatchTextBgClass">
         //         <div class="swatchInnerText">4-Pack</div>
         //       </div>
         //       <div class="selectedArrow"></div>
         //   </div>
         //           </a>
         //   </div>

         //   <div title="Click to select  6-Pack" tabindex="0" class="swatchOuter" count=4 key=size_name >
         //       <a href="http://www.amazon.com/gp/product/B003BIG0E8/ref=twister_B000AST3AK?ie=UTF8&psc=1">
         //       <div id="size_name_4" class=swatchAvailable >
         //       <div class="swatchTextBgClass">
         //         <div class="swatchInnerText">6-Pack</div>
         //       </div>
         //       <div class="selectedArrow"></div>
         //   </div>
         //           </a>
         //   </div>

         //<div style="height:5px;clear:both;"></div>
         //</div>


        //http://www.amazon.com/Thermos-Insulated-18-Ounce-Stainless-Steel-Hydration/dp/B000FJ9DOK/ref=lp_1055398_1_6?ie=UTF8&qid=1370574186&sr=1-6
        //has 3 variation
        //<div id=selected_color_name class="variationSelected">
        //   <b class="variationDefault">Color:  </b>
        //   <b class="variationLabel">Stainless Steel</b>
        //</div>
 
        //<div class="clearfix spacediv"> 
  
        //      <div title="Click to select  Stainless Steel" tabindex="0" class="swatchOuter"
        //    count=0 key=color_name >
        //      <div id=color_name_0 class=swatchSelect >
        //        <div class="swatchImageOverlay">
        //                 <div style="background-image: url(http://ecx.images-amazon.com/images/I/319bboSRXAL._SX36_SY36_CR,0,0,36,36_.jpg );" class="swatchInnerImage">
        //           </div>
        //        </div>
        //              <div class="selectedArrow"></div>
        //      </div>
        //        </div>
 
        //      <div title="Click to select  Charcoal" tabindex="0" class="swatchOuter"
        //    count=1 key=color_name >
        //       <a href="http://www.amazon.com/gp/product/B0057FQCNC/ref=twister_B000FJ9DOK?ie=UTF8&psc=1">
        //      <div id=color_name_1 class=swatchAvailable >
        //        <div class="swatchImageOverlay">
        //                 <div style="background-image: url(http://ecx.images-amazon.com/images/I/31WdbMpihIL._SX36_SY36_CR,0,0,36,36_.jpg );" class="swatchInnerImage">
        //           </div>
        //        </div>
        //              <div class="selectedArrow"></div>
        //      </div>
        //       </a>
        //        </div>
  
        //      <div title="Click to select  Midnight Blue" tabindex="0" class="swatchOuter"
        //    count=2 key=color_name >
        //       <a href="http://www.amazon.com/gp/product/B0057FQCXW/ref=twister_B000FJ9DOK?ie=UTF8&psc=1">
        //      <div id=color_name_2 class=swatchAvailable >
        //        <div class="swatchImageOverlay">
        //                 <div style="background-image: url(http://ecx.images-amazon.com/images/I/313WcHfdPhL._SX36_SY36_CR,0,0,36,36_.jpg );" class="swatchInnerImage">
        //           </div>
        //        </div>
        //              <div class="selectedArrow"></div>
        //      </div>
        //       </a>
        //        </div>
 
        //<div style="height:5px;clear:both;"></div>
        //</div>


        //http://www.amazon.com/Glad-Kitchen-Drawstring-Garbage-Gallon/dp/B005GSYXHW/ref=lp_1055398_1_8?ie=UTF8&qid=1370574186&sr=1-8
        //has 2 variation

        //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_9?ie=UTF8&qid=1370574186&sr=1-9
        //has 3 variation


        //http://www.amazon.com/Sundesa-BB28-SC08-BlenderBottle%C2%AE-Classic-28-ounce/dp/B001KADGMI/ref=zg_bs_appliances_8/184-1909798-9660844
        //two group -> 3x8=24 variation

        //example url:
        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_6?ie=UTF8&qid=1369727413&sr=1-6


        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=zg_bs_appliances_1/178-1487576-1992961
        //5 variation
        //<div class="buying">
        //  <strong>
        //  <label for="asinRedirect">Size Name:</label>
        //  </strong><br />
        //  <select name="asin-redirect" id="asinRedirect" onchange="gotoDetailPage(this)">
        //    <option value="B000AST3AK"  selected="selected" title="1-Pack">1-Pack</option><option value="B003BIG0DO"  title="2-Pack">2-Pack</option><option value="B00149JVOC"  title="3 Pack">3 Pack</option><option value="B003BIG0DY"  title="4-Pack">4-Pack</option><option value="B003BIG0E8"  title="6-Pack">6-Pack</option>
        //  </select>

        //init
        string productHtml = crl.getUrlRespHtml_multiTry(productUrl);
        HtmlDocument htmlDoc = crl.htmlToHtmlDoc(productHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;

        HtmlNode selectAsinNode = rootNode.SelectSingleNode("//select[@name='asin-redirect' and @id='asinRedirect']");

        //1.find current selected
        HtmlNode curSelectNode = rootNode.SelectSingleNode("//div[@class='variationSelected']");
        if (curSelectNode != null)
        {
            HtmlNode variationLabelNode = curSelectNode.SelectSingleNode("./b[@class='variationLabel']");
            if (variationLabelNode != null)
            {
                string selectedVariationLable = variationLabelNode.InnerText;
                variationInfo.curSelectLable = selectedVariationLable;

                //2.find all variations
                HtmlNodeCollection swatchNodeList = rootNode.SelectNodes("//div[contains(@title, 'Click to select') and @class='swatchOuter' and @count and @key]");
                if ((swatchNodeList != null) && (swatchNodeList.Count > 0))
                {
                    for(int idx = 0; idx < swatchNodeList.Count; idx++)
                    {
                        variationItem singleVariationItem = new variationItem();
                        HtmlNode swatchNode = swatchNodeList[idx];

                        //<div title="Click to select  2-Pack" tabindex="0" class="swatchOuter" count=1 key=size_name >
                        //    <a href="http://www.amazon.com/gp/product/B003BIG0DO/ref=twister_B000AST3AK?ie=UTF8&psc=1">
                        //    <div id="size_name_1" class=swatchAvailable >
                        //    <div class="swatchTextBgClass">
                        //        <div class="swatchInnerText">2-Pack</div>
                        //    </div>
                        //    <div class="selectedArrow"></div>
                        //</div>
                        //        </a>
                        //</div>

                        //<div title="Click to select  Charcoal" tabindex="0" class="swatchOuter"
                        //count=1 key=color_name >
                        //<a href="http://www.amazon.com/gp/product/B0057FQCNC/ref=twister_B000FJ9DOK?ie=UTF8&psc=1">
                        //<div id=color_name_1 class=swatchAvailable >
                        //    <div class="swatchImageOverlay">
                        //            <div style="background-image: url(http://ecx.images-amazon.com/images/I/31WdbMpihIL._SX36_SY36_CR,0,0,36,36_.jpg );" class="swatchInnerImage">
                        //    </div>
                        //    </div>
                        //        <div class="selectedArrow"></div>
                        //</div>
                        //</a>
                        //    </div>


                        //some no "swatchInnerText"
                        //so just extract variation label from title
                        string divTitleStr = swatchNode.Attributes["title"].Value;//Click to select  Stainless Steel
                        string variationLable = divTitleStr.Replace("Click to select  ", "");//Stainless Steel
                        singleVariationItem.label = variationLable;

                        HtmlNode swatchANode = swatchNode.SelectSingleNode("./a[@href]");
                        if (swatchANode != null)
                        {
                            singleVariationItem.url = swatchANode.Attributes["href"].Value;
                        }
                        else
                        {
                            //this one is current selected
                            //->
                            //(1)label should be same
                            //->
                            //(1)this node no url
                            //(2)set above current selected index in variation list
                            //
                            if (singleVariationItem.label.Equals(variationInfo.curSelectLable))
                            {
                                singleVariationItem.url = variationInfo.curSelectUrl;
                                variationInfo.curSelectdIdx = idx;
                            }
                            else
                            {
                                //something wrong
                                gLogger.Debug("selected label find from html not equal with current real selected label, for url=" + productUrl);
                            }
                        }


                        //HtmlNode swatchTextNode = swatchNode.SelectSingleNode(".//div[@class='swatchInnerText']");
                        //if (swatchTextNode != null)
                        //{
                        //    string variationLable = swatchTextNode.InnerText;
                        //    singleVariationItem.label = variationLable;

                        //    if (singleVariationItem.label.Equals(variationInfo.curSelectLable))
                        //    {


                        //        singleVariationItem.url = variationInfo.curSelectUrl;
                        //        variationInfo.curSelectdIdx = idx;
                        //    }
                        //    else
                        //    {
                        //        //get url from html node
                        //        HtmlNode swatchANode = swatchNode.SelectSingleNode("./a[@href]");

                        //    }
                        //}
                        //else
                        //{
                        //    //something wrong
                        //}

                        variationInfo.variationList.Add(singleVariationItem);
                    }

                    foundVariation = true;
                }
                else
                {
                    //something wrong
                    gLogger.Debug("swatchNodeList is null or count <= 0 for url=" + productUrl);
                }
            }
            else
            {
                //something wrong

                //special: no variationLabel
                //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1370574186&sr=1-1
                //has two group -> 4 variation

                //<input type="hidden" name="variationDimensionValue.B0083PWAPW" value="16 GB,With Special Offers"/>
                //<input type="hidden" name="variationDimensionValue.B007T36PSM" value="16 GB,Without Special Offers"/>
                //<input type="hidden" name="variationDimensionValue.B008SYWFNA" value="32 GB,With Special Offers"/>
                //<input type="hidden" name="variationDimensionValue.B009D7BJR4" value="32 GB,Without Special Offers"/>

                HtmlNodeCollection variationDimenstionNodeList = rootNode.SelectNodes("//input[@type='hidden' and contains(@name, 'variationDimensionValue.') and @value]");
                if ((variationDimenstionNodeList != null) && (variationDimenstionNodeList.Count > 0))
                {
                    for (int idx = 0; idx < variationDimenstionNodeList.Count; idx++)
                    {
                        HtmlNode variationDimenstionNode = variationDimenstionNodeList[idx];
                        variationItem singleVariationItem = new variationItem();

                        singleVariationItem.label = variationDimenstionNode.Attributes["value"].Value; //16 GB,With Special Offers

                        string nameValueStr = variationDimenstionNode.Attributes["name"].Value; //variationDimensionValue.B0083PWAPW
                        string variationAsin = nameValueStr.Replace("variationDimensionValue.", ""); //B0083PWAPW
                        
                        //check whether is current selected
                        if (extractedAsin.Equals(variationAsin, StringComparison.CurrentCultureIgnoreCase))
                        {
                            //is current selected
                            variationInfo.curSelectdIdx = idx;
                            variationInfo.curSelectLable = singleVariationItem.label;
                            singleVariationItem.url = variationInfo.curSelectUrl;
                        }
                        else
                        {
                            string generatedProductUrl = generateProductUrlFromAsin(variationAsin);
                            singleVariationItem.url = generatedProductUrl;
                        }

                        variationInfo.variationList.Add(singleVariationItem);
                    }

                    foundVariation = true;
                }
                else
                {
                    //something wrong
                    //or no variation ?
                    gLogger.Debug("variationDimenstionNodeList is null or count <= 0 -> something wrong or no variation ? for url=" + productUrl);
                }
            }
        }
        else if (selectAsinNode != null)
        {
            //<select name="asin-redirect" id="asinRedirect" onchange="gotoDetailPage(this)">
            //    <option value="B000AST3AK"  selected="selected" title="1-Pack">1-Pack</option>
            //    <option value="B003BIG0DO"  title="2-Pack">2-Pack</option>
            //    <option value="B00149JVOC"  title="3 Pack">3 Pack</option>
            //    <option value="B003BIG0DY"  title="4-Pack">4-Pack</option>
            //    <option value="B003BIG0E8"  title="6-Pack">6-Pack</option>
            //</select>
            HtmlNodeCollection optionNodeList = selectAsinNode.SelectNodes("./option[@value]");
            if ((optionNodeList != null) && (optionNodeList.Count > 0))
            {
                for (int idx = 0; idx < optionNodeList.Count; idx++)
                {
                    HtmlNode optionNode = optionNodeList[idx];
                    variationItem singleVariationItem = new variationItem();

                    string titleValue = optionNode.Attributes["title"].Value;
                    singleVariationItem.label = titleValue;

                    if (optionNode.Attributes.Contains("selected"))
                    {
                        //is current selected
                        variationInfo.curSelectdIdx = idx;
                        variationInfo.curSelectLable = singleVariationItem.label;
                        singleVariationItem.url = variationInfo.curSelectUrl;
                    }
                    else
                    {
                        string asinStr = optionNode.Attributes["value"].Value;
                        string generatedProductUrl = generateProductUrlFromAsin(asinStr); //"http://www.amazon.com/gp/product/B003BIG0DO"
                        singleVariationItem.url = generatedProductUrl;
                    }

                    variationInfo.variationList.Add(singleVariationItem);
                }

                foundVariation = true;
            }
            else
            {
                //somethin wrong
                gLogger.Debug("optionNodeList is null or count <= 0");
            }
        }
        else
        {
            gLogger.Debug("no variation for " + productUrl);
            //no viration
            //http://www.amazon.com/Paderno-World-Cuisine-A4982799-Tri-Blade/dp/B0007Y9WHQ/ref=lp_1055398_1_4?ie=UTF8&qid=1370591290&sr=1-4
            //http://www.amazon.com/Ziploc-Space-Bag-Saver-Set/dp/B00BEBXH5O/ref=lp_1055398_1_5?ie=UTF8&qid=1370591290&sr=1-5
            //...

            //or something wrong ?
        }

        return foundVariation; 
    }

    /*
     * [Function]
     * from html extract buyer number and used and new url
     * [Input]
     * amazon product url's html
     * [Output]
     * buyer number and used and new url
     * [Note]
     */
    public bool extractProductBuyerNumberAndNewUrl(string productHtml, out int totalBuyerNumber, out string usedAndNewUrl)
    {
        bool extractOk = false;

        totalBuyerNumber = 0;
        usedAndNewUrl = "";

        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(productHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;

        /*
          <div class="mbcContainer">
            <div class="mbcTitle">More Buying Choices</div>
            <div id="more-buying-choice-content-div">
        <div id="secondaryUsedAndNew" class="mbcOlp" style="text-align:center;">
        <div class="mbcOlpLink" ><a class="buyAction" href="/gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all">18&nbsp;used&nbsp;&&nbsp;new</a>&nbsp;from&nbsp;<span class="price">$180.00</span></div>
        </div>
            </div>
          </div>
         */
        HtmlNode mbcNode = rootNode.SelectSingleNode("//div[@class='mbcContainer']");
        if (mbcNode != null)
        {
            HtmlNode buyActionNode = mbcNode.SelectSingleNode("./div[@id='more-buying-choice-content-div']/div[@id='secondaryUsedAndNew']/div[@class='mbcOlpLink']/a[@class='buyAction']");
            if (buyActionNode != null)
            {
                //find url for "18 used & new "
                usedAndNewUrl = buyActionNode.Attributes["href"].Value; ///gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all
                usedAndNewUrl = constAmazonDomainUrl + usedAndNewUrl;//http://www.amazon.com/gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all

                string buyActionStr = buyActionNode.InnerText; //18&nbsp;used&nbsp;&&nbsp;new
                string buyNumberStr = "";
                if (crl.extractSingleStr(@"^(\d+)", buyActionStr, out buyNumberStr))
                {
                    int buyNumberInt = Int32.Parse(buyNumberStr); //18
                    totalBuyerNumber = buyNumberInt;
                    extractOk = true;
                }
            }
        }

        return extractOk;
    }

    /*
     * [Function]
     * extract product seller info from current page html
     * [Input]
     * html of:
     * http://www.amazon.com/gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all
     * or:
     * http://www.amazon.com/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_page_next?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&shipPromoFilter=0&sort=sip&sr=&startIndex=15
     * [Output]
     * list of product sellers' info
     * [Note]
     */
    public List<productSellerInfo> extractSinglePageSellerInfo(string curPageSellerUrl, string curPageSellerHtml)
    {
        List<productSellerInfo> curPageSellerInfoList = new List<productSellerInfo>();

        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(curPageSellerHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;
        
        //http://www.amazon.com/gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all
        //<tbody class="result">
        //    <tr>
        //        <td>
        //            <span class="price">$199.00</span>
        //            ......
        //        </td>
        //        <td>
        //            <div class="condition">
        //                New
        //            </div>
        //        </td>
        //        <td>
        //            <ul class="sellerInformation">
        //                <img src="http://ecx.images-amazon.com/images/I/01dXM-J1oeL.gif" width="90" alt="Amazon.com" title="Amazon.com" height="17" border="0" /><br>
        

        //<tbody class="result">
        //    <tr>
        //        <td>
        //            <span class="price">$167.00</span>
        //                <div class="shipping_block">
        //                    <span class="price_shipping">+ $5.49</span><span class="word_shipping">shipping</span>
        //                </div>
        //        </td>
        //        <td>
        //            <div class="condition">
        //                Used
        //                    - Very Good
        //            </div>
        //        ......
        //        </td>
        //        <td>
        //            <ul class="sellerInformation">
        //                <a href="http://www.amazon.com/shops/AGG9XFCRV9ZLM/ref=olp_merch_name_2">
        //                    <img src="http://ecx.images-amazon.com/images/I/31UM0OH423L.jpg" width="120" alt="*raman*" title="*raman*" height="30" border="0" />
        //                </a>
        //                <br>


        //<tbody class="result">
        //    <tr>
        //        <td>
        //            <span class="price">$167.99</span>
        //            <div class="shipping_block">
        //                <span class="price_shipping">+ $5.07</span><span class="word_shipping">shipping</span>
        //            </div>
        //        </td>
        //        <td>
        //            <div class="condition">
        //                Used
        //                    - Very Good
        //            </div>
        //            ......
        //        </td>
        //        <td>
        //            <ul class="sellerInformation">
        //                <li>
        //                    <div class="seller">
        //                            <span class="sellerHeader">Seller:</span>
        //                            <a href="/gp/aag/main/ref=olp_merch_name_3?ie=UTF8&amp;asin=B0083PWAPW&amp;isAmazonFulfilled=0&amp;seller=A2OZA7BZOXAODK">
        //                                <b>windwing</b>
        //                            </a>
        //                    </div>
        //                </li>


        HtmlNodeCollection oldOfferNodeList = null;
        if (oldOfferNodeList == null)
        {
            //http://www.amazon.com/gp/offer-listing/B0005YWH7A/ref=dp_olp_new_mbc?ie=UTF8&condition=new
            //<div class='a-row a-spacing-medium olpOffer'>
            //  <div class='a-column a-span2'>
            //  <span class='a-size-large a-color-price olpOfferPrice a-text-bold'>$40.37</span> 
            //  <span class='a-color-price'>
            //    <span class="pricePerUnit">($6.73 / Item)</span>
            //  </span>
            //  <p>
            //    <span class='a-color-secondary'>+ 
            //    <span class="olpShippingPrice">$0.00</span> 
            //    <span class="olpShippingPriceText">shipping</span></span>
            //  </p></div>
            //  <div class='a-column a-span3'>
            //    <div class='a-section a-spacing-small'>
            //      <span class='a-size-medium olpCondition a-text-bold'>New</span>
            //    </div>
            //  </div>
            //  <div class='a-column a-span5 olpSellerColumn'>
            //    <p class='a-spacing-small olpSellerName'>
            //      <a href="http://www.amazon.com/shops/A2KFAF0QS92MUL/ref=olp_merch_name_1">
            //        <img src="http://ecx.images-amazon.com/images/I/11SmRBFO9mL.gif" width="120" alt="Nutricity" title="Nutricity"
            //        height="30" border="0" />
            //      </a>
            //      <br />
            //    </p>
            //    <p class='a-spacing-small'>
            //      <span class="olpSellerRating">
            //      <img src="http://g-ecx.images-amazon.com/images/G/01/detail/stars-4-5._V192261415_.gif" width="64" alt=""
            //      class="olpSellerStars" height="12" border="0" /> 
            //      <a href="/gp/aag/main/ref=olp_merch_rating_1?ie=UTF8&amp;asin=B0005YWH7A&amp;isAmazonFulfilled=0&amp;seller=A2KFAF0QS92MUL">

            //        <b>91% positive</b>
            //      </a> over the past 12 months. (85,821 total ratings)</span>
            //    </p>
            //    <div class="olpAvailability">Usually ships within 4 - 5 business days. Expedited shipping available.
            //    <br />
            //    <a href="/gp/aag/details/ref=olp_merch_ship_1?ie=UTF8&amp;asin=B0005YWH7A&amp;seller=A2KFAF0QS92MUL&amp;sshmPath=shipping-rates#aag_shipping">
            //    International &amp; domestic shipping rates</a> and 
            //    <a href="/gp/aag/details/ref=olp_merch_return_1?ie=UTF8&amp;asin=B0005YWH7A&amp;seller=A2KFAF0QS92MUL&amp;sshmPath=returns#aag_returns">
            //    return policy</a>.</div>
            //    <p class='a-spacing-small'></p>
            //  </div>
            //  <div class='a-column a-span2 olpBuyColumn a-span-last'>
            //    <div class='a-button-stack'>
            //      <form method='post' action='/gp/item-dispatch/ref=olp_atc_fm_1' class='olpCartForm'>
            //      <input type="hidden" name="session-id" value="175-2006876-3576307" /> 
            //      <input type="hidden" name="qid" value="" /> 
            //      <input type="hidden" name="sr" value="" /> 
            //      <input type="hidden" name="signInToHUC" value="0" id="signInToHUC" /> 
            //      <input type="hidden" name="metric-asin.B0005YWH7A" value="1" /> 
            //      <input type="hidden" name="registryItemID.1" value="" /> 
            //      <input type="hidden" name="registryID.1" value="" /> 
            //      <input type="hidden" name="itemCount" value="1" /> 
            //      <input type="hidden" name="offeringID.1"
            //      value="BOUi4w9LxovFkpVlVIG66MCDi2r7fL3YHUylSFaasglaVBwmi3KH9rTEMFHjKLxKRY1FSrrKNeQzp6n734Of1uM7EGPueHxh9JGpIanOKbgz6qg%2F2BqfiVka07bIepRxagzydeUwLa8HMSP%2FmUlHuQ%3D%3D" />

            //      <input type="hidden" name="isAddon" value="0" /> 
            //      <span class='a-button a-button-primary a-button-icon'>
            //        <span class='a-button-inner'>
            //        <input name='submit.addToCart' class='a-button-input' type='submit' value='Add to cart' /> 
            //        <span class='a-button-text'>Add to cart</span></span>
            //      </span></form>
            //      <p class='a-spacing-micro a-text-center'>or</p>
            //      <p class='a-spacing-none a-text-center olpSignIn'>
            //      <a href="https://www.amazon.com/gp/product/utility/edit-one-click-pref.html/ref=olp_offerlisting_1?ie=UTF8&amp;returnPath=%2Fgp%2Foffer-listing%2FB0005YWH7A">
            //      Sign in</a> to turn on 1-Click ordering.</p>
            //    </div>
            //  </div>
            //</div>

            oldOfferNodeList = rootNode.SelectNodes("//div[@class='a-row a-spacing-medium olpOffer']");
        }

        if (oldOfferNodeList == null)
        {
            //http://www.amazon.com/gp/offer-listing/B0009P5YXO/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr=
            //<div class='a-row a-spacing-mini olpOffer'>
            //    <div class='a-column a-span2'>
            //        <span class='a-size-large a-color-price olpOfferPrice a-text-bold'>        $24.98    </span>
            //        ......
            //        <p class='a-spacing-small olpSellerName'>
            //            <a href="http://www.amazon.com/shops/AVX4MBCC3Z0US/ref=olp_merch_name_2"><img src="http://ecx.images-amazon.com/images/I/11IOQefmgaL.gif" width="120" alt="Comics-N-Stuff" title="Comics-N-Stuff" height="30" border="0"></a><br>
            //        </p>

            oldOfferNodeList = rootNode.SelectNodes("//div[@class='a-row a-spacing-mini olpOffer']");
        }


        HtmlNodeCollection resultBodyNodeList = rootNode.SelectNodes("//tbody[@class='result']");
        if ((resultBodyNodeList != null) && (resultBodyNodeList.Count > 0))
        {
            foreach (HtmlNode eachSellerNode in resultBodyNodeList)
            {
                productSellerInfo sellerInfo = new productSellerInfo();
                bool getCurSellerInfoOk = true;

                //1. seller name
                //type1: image, contain title(name), also contain link
                HtmlNode imgNode = eachSellerNode.SelectSingleNode(".//ul[@class='sellerInformation']//img[@src and @title]");
                if (imgNode != null)
                {
                    string imgTitle = imgNode.Attributes["title"].Value;//Amazon.com
                    sellerInfo.name = imgTitle;
                }
                else
                {
                    //type2: seller name, with link
                    HtmlNode sellerBNode = eachSellerNode.SelectSingleNode(".//ul[@class='sellerInformation']//div[@class='seller']/a/b");
                    if (sellerBNode != null)
                    {
                        string sellerName = sellerBNode.InnerText;//windwing
                        sellerInfo.name = sellerName;
                    }
                    else
                    {
                        //something wrong ?
                        gLogger.Warn("not find sellerBNode for " + curPageSellerUrl);
                        
                        getCurSellerInfoOk = false;
                    }
                }

                //2. seller price
                //<span class="price">$167.99</span>
                HtmlNode priceNode = eachSellerNode.SelectSingleNode(".//span[@class='price']");
                if (priceNode != null)
                {
                    string priceDollarStr = priceNode.InnerText; // $199.00
                    string priceStr = priceDollarStr.Replace("$", "");
                    sellerInfo.price = float.Parse(priceStr);
                }
                else
                {
                    //something wrong

                    //or special:
                    //http://www.amazon.com/gp/offer-listing/B0057OCDQS/sr=/qid=/ref=olp_page_next?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&shipPromoFilter=0&sort=sip&sr=&startIndex=15
                    //no price:
                    //<tr>
                    //    <td>
                    //        <span>Add to cart to see product details.</span>
                    //        <div class="shipping_block">
                    //            <span class="price_shipping">+ $0.00</span><span class="word_shipping">shipping</span>
                    //        </div>
                    //    </td>
                    //    <td>
                    gLogger.Debug("not find priceNode for " + curPageSellerUrl);

                    getCurSellerInfoOk = false;
                }

                if (getCurSellerInfoOk)
                {
                    curPageSellerInfoList.Add(sellerInfo);
                }
            }
        }
        else if ((oldOfferNodeList != null) && (oldOfferNodeList.Count > 0))
        {
            foreach (HtmlNode oldOfferNode in oldOfferNodeList)
            {
                productSellerInfo sellerInfo = new productSellerInfo();
                bool getCurSellerInfoOk = true;

                //1. seller name
                //<div class='a-column a-span5 olpSellerColumn'>
                //  <p class='a-spacing-small olpSellerName'>
                //    <a href="http://www.amazon.com/shops/A2KFAF0QS92MUL/ref=olp_merch_name_1">
                //      <img src="http://ecx.images-amazon.com/images/I/11SmRBFO9mL.gif" width="120" alt="Nutricity" title="Nutricity"
                //      height="30" border="0" />
                //    </a>

                //<div class='a-column a-span5 olpSellerColumn'>
                //  <p class='a-spacing-small olpSellerName'>
                //    <img src="http://ecx.images-amazon.com/images/I/01dXM-J1oeL.gif" width="90" alt="Amazon.com" title="Amazon.com" height="17"
                //    border="0" />
                //    <br />
                //  </p>

                //HtmlNode imgNode = oldOfferNode.SelectSingleNode(".//div[contains(@class,'olpSellerColumn')]/p[contains(@class, 'olpSellerName')]/a/img[@src and @title]");
                //HtmlNode sellerANode = oldOfferNode.SelectSingleNode(".//div[contains(@class,'olpSellerColumn')]/p[contains(@class, 'olpSellerName')]/a");
                //HtmlNode sellerANode = oldOfferNode.SelectSingleNode(".//div[contains(@class,'olpSellerColumn')]/p[contains(@class, 'olpSellerName')]//a");
                HtmlNode olpSellerNameNode = oldOfferNode.SelectSingleNode(".//div[contains(@class,'olpSellerColumn')]/p[contains(@class, 'olpSellerName')]");

                if (olpSellerNameNode != null)
                {
                    HtmlNode imgNode = olpSellerNameNode.SelectSingleNode(".//img[@src and @title]");
                    if (imgNode != null)
                    {
                        //type1: image, contain title(name), also contain link
                        string imgTitle = imgNode.Attributes["title"].Value;//Nutricity
                        sellerInfo.name = imgTitle;
                    }
                    else
                    {
                        //<div class='a-column a-span5 olpSellerColumn'>
                        //<p class='a-spacing-small olpSellerName'>
                        //    <span class='a-size-medium'>
                        //    <a href="/gp/aag/main/ref=olp_merch_name_4?ie=UTF8&amp;asin=B0005YWH7A&amp;isAmazonFulfilled=0&amp;seller=A2YPCK6GWDEH36">
                        //        <b>Jupiter&#39;s</b>
                        //    </a>
                        //    </span>
                        //</p>

                        HtmlNode aSizeMediumTitleNode = null;
                        if (aSizeMediumTitleNode == null)
                        {
                            //<span class='a-size-medium'>
                            //    <a href="/gp/aag/main/ref=olp_merch_name_2?ie=UTF8&amp;asin=B001FA1L9I&amp;isAmazonFulfilled=0&amp;seller=A2RT9A30B947NZ"><b>Premier Life</b></a>
                            //</span>
                            aSizeMediumTitleNode = olpSellerNameNode.SelectSingleNode("./span[@class='a-size-medium']/a/b");
                        }

                        if (aSizeMediumTitleNode == null)
                        {
                            //<span class='a-size-medium a-text-bold'>
                            //    <a href="/gp/aag/main/ref=olp_merch_name_11?ie=UTF8&amp;asin=B0009P5YXO&amp;isAmazonFulfilled=0&amp;seller=A1TSQ9D0EY9488">kumrai</a>
                            //</span>
                            aSizeMediumTitleNode = olpSellerNameNode.SelectSingleNode("./span[@class='a-size-medium a-text-bold']/a");
                        }
                        if (aSizeMediumTitleNode != null)
                        {
                            string sellerName = aSizeMediumTitleNode.InnerText;//"Jupiter's"
                            sellerInfo.name = sellerName;
                        }
                        else
                        {
                            //something wrong ?
                            gLogger.Warn("not find oldOfferNode's aSizeMediumTitleNode for " + curPageSellerUrl);

                            getCurSellerInfoOk = false;
                        }
                    }
                }
                else
                {
                    //something wrong ?
                    gLogger.Warn("not find oldOfferNode's olpSellerNameNode for " + curPageSellerUrl);
                }

                //2. seller price
                //<span class='a-size-large a-color-price olpOfferPrice a-text-bold'>$40.37</span> 
                HtmlNode priceNode = oldOfferNode.SelectSingleNode(".//span[contains(@class, 'olpOfferPrice')]");
                if (priceNode != null)
                {
                    string priceDollarStr = priceNode.InnerText; //"\n        $40.37\n    "
                    string priceStr = priceDollarStr.Replace("$", "").Trim(); //"40.37"
                    sellerInfo.price = float.Parse(priceStr);
                }
                else
                {
                    //something wrong ?
                    //or some special:
                    //http://www.amazon.com/gp/offer-listing/B003H7B78M/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr=
                    //Tucker's Toy Shop
                    //no price, only:  Add to cart to see product details. 
                    gLogger.Debug("not find oldOfferNode's priceNode for " + curPageSellerUrl);

                    getCurSellerInfoOk = false;
                }

                if (getCurSellerInfoOk)
                {
                    curPageSellerInfoList.Add(sellerInfo);
                }
            }
        }
        else
        {
            //special:
            //http://www.amazon.com/gp/offer-listing/B000FJ9DOK/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr=
            //We're sorry. There are currently no Used listings for

            //something wrong ?

            gLogger.Debug("not find priceNode for " + curPageSellerUrl);
        }
       
        return curPageSellerInfoList;
    }

    /*
     * [Function]
     * extract all single type(New/Used) product seller info from its url
     * [Input]
     * http://www.amazon.com/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr=
     * or:
     * http://www.amazon.com/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr=
     * [Output]
     * list of product sellers' info
     * [Note]
     */
    public List<productSellerInfo> extractAllSingleTypeSellerInfo(string singleTypeUrl)
    {
        List<productSellerInfo> allSellerInfoList = new List<productSellerInfo>();
        List<productSellerInfo> curPageSellerInfoList = new List<productSellerInfo>();

        string curPageSellerUrl = singleTypeUrl;

        while (true)
        {
            string curPageSellerHtml = crl.getUrlRespHtml_multiTry(curPageSellerUrl);
            curPageSellerInfoList = extractSinglePageSellerInfo(curPageSellerUrl, curPageSellerHtml);
            if ((curPageSellerInfoList != null) && (curPageSellerInfoList.Count > 0))
            {
                allSellerInfoList.AddRange(curPageSellerInfoList);
            }
            else
            {
                //something wrong ?
                //maybe empty seller ?
                
                //http://www.amazon.com/gp/offer-listing/B000AST3AK/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr=
                //We're sorry. There are currently no Used listings for ......

                //so no need break here
                //break;

                gLogger.Debug("not find current page seller info for " + curPageSellerUrl);
            }

            //find next page url

            //<div class="pagination">
            //    <div class="pages">
            //        <span class="nexton">&#171;&nbsp;Previous</span>
            //        <span class="pagenumberon">1</span><a href="/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_page_2?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=used&amp;me=&amp;qid=&amp;shipPromoFilter=0&amp;sort=sip&amp;sr=&amp;startIndex=15"  id="page_1" class="pagenumberoff" >2</a>
            //        <a href="/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_page_next?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=used&amp;me=&amp;qid=&amp;shipPromoFilter=0&amp;sort=sip&amp;sr=&amp;startIndex=15"  id="olp_page_next" class="nextoff" >Next&nbsp;&#187;</a>
            //    </div>
            //</div>

            //http://www.amazon.com/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr=
            //<div class="pagination">
            //    <div class="pages">
            //        <span class="nexton">&#171;&nbsp;Previous</span>
            //        <span class="pagenumberon">1</span>
            //        <span class="nexton">Next&nbsp;&#187;</span>
            //    </div>
            //</div>

            HtmlAgilityPack.HtmlDocument curPageHtmlDoc = crl.htmlToHtmlDoc(curPageSellerHtml);
            HtmlNode curPageRootNode = curPageHtmlDoc.DocumentNode;
            HtmlNode pageNextNode = curPageRootNode.SelectSingleNode("//a[@id='olp_page_next' and @class='nextoff']");

            if (pageNextNode == null)
            {
                //http://www.amazon.com/gp/offer-listing/B001FA1L9I/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr=
                //<div class="a-pagination a-text-center a-spacing-large">
                //  <ul class="a-pagination">
                //    <li class="a-disabled">←Previous</li>
                //    <li class="a-selected">
                //      <a href="">1</a>
                //    </li>
                //    <li>
                //      <a href="/gp/offer-listing/B001FA1L9I/sr=/qid=/ref=olp_page_2?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;shipPromoFilter=0&amp;sort=sip&amp;sr=&amp;startIndex=10">
                //      2</a>
                //    </li>
                //    <li class="a-last">
                //      <a href="/gp/offer-listing/B001FA1L9I/sr=/qid=/ref=olp_page_next?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;shipPromoFilter=0&amp;sort=sip&amp;sr=&amp;startIndex=10">
                //      Next→</a>
                //    </li>
                //  </ul>
                //</div>
                pageNextNode = curPageRootNode.SelectSingleNode("//ul[@class='a-pagination']//li[@class='a-last']/a");
            }

            if (pageNextNode != null)
            {
                string pageNextHref = pageNextNode.Attributes["href"].Value;
                string rawPageNextUrl = constAmazonDomainUrl + pageNextHref;
                string pageNextUrl = HttpUtility.HtmlDecode(rawPageNextUrl); //"http://www.amazon.com/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_page_next?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&shipPromoFilter=0&sort=sip&sr=&startIndex=15"

                curPageSellerUrl = pageNextUrl;
            }
            else
            {
                //Next is empty
                break;
            }
        }//while

        return allSellerInfoList;
    }

    /*
     * [Function]
     * extract all product seller info from usedAndNewUrl, include New and Used
     * [Input]
     * http://www.amazon.com/gp/offer-listing/B0083PWAPW/ref=dp_olp_all_mbc?ie=UTF8&condition=all
     * http://www.amazon.com/gp/offer-listing/B007OZNZG0/ref=dp_olp_all_mbc?ie=UTF8&condition=all
     * http://www.amazon.com/gp/offer-listing/B0007Y9WHQ/ref=dp_olp_all_map_mbc?ie=UTF8&condition=all
     * [Output]
     * list of product sellers' info
     * [Note]
     */
    public bool extractAllSellerInfo(string usedAndNewUrl, out List<productSellerInfo> allSellerInfoList)
    {
        bool extractSellerInfoOk = false;
        allSellerInfoList = new List<productSellerInfo>();

        List<productSellerInfo> singleTypeAllSellerInfoList = new List<productSellerInfo>();

        string usedAndNewHtml = crl.getUrlRespHtml_multiTry(usedAndNewUrl);
        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(usedAndNewHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;

        //1. find url for New and Used
        //<table id="metatabs" cellspacing="0">
        //    <tr id="metatabrow">
        //            <td id="all" class="olplefton inactive">
        //                <a href="/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_all?ie=UTF8&amp;colid=&amp;coliid=&amp;me=&amp;qid=&amp;seller=&amp;sr=">All</a>
        //            </td>
        //            <td id="new" class="olpmiddleoffonleft">
        //                <a href="/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_new?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;seller=&amp;sr=">&nbsp;New&nbsp;<span class="numberreturned">from $199.00</span>&nbsp;</a>
        //            </td>
        //            <td id="used" class="olpmiddleoff">
        //                <a href="/gp/offer-listing/B0083PWAPW/sr=/qid=/ref=olp_tab_used?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=used&amp;me=&amp;qid=&amp;seller=&amp;sr=">&nbsp;Used&nbsp;<span class="numberreturned">from $167.00</span>&nbsp;<span class="olpPercentOff">(Save  <b>16</b>%)</span></a>
        //            </td>

        //        <td class="olprightoff">&nbsp;&nbsp;</td>
        //    </tr>
        //</table>

        //http://www.amazon.com/gp/offer-listing/B000FJ9DOK/ref=dp_olp_new_mbc?ie=UTF8&condition=new
        //<table id="metatabs" cellspacing="0">
        //    <tr id="metatabrow">
        //            <td id="all" class="olpleftoff">
        //                <a href="/gp/offer-listing/B000FJ9DOK/sr=/qid=/ref=olp_tab_all?ie=UTF8&amp;colid=&amp;coliid=&amp;me=&amp;qid=&amp;seller=&amp;sr=">All</a>
        //            </td>
        //            <td id="new" class="olpmiddleon inactive">
        //                <a href="/gp/offer-listing/B000FJ9DOK/sr=/qid=/ref=olp_tab_new?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;seller=&amp;sr=">&nbsp;New&nbsp;<span class="numberreturned">from $13.57</span>&nbsp;<span class="olpPercentOff">(Save  <b>41</b>%)</span></a>
        //            </td>
        //            <td id="used" class="olpmiddleoffonleft">
        //                <a href="/gp/offer-listing/B000FJ9DOK/sr=/qid=/ref=olp_tab_used?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=used&amp;me=&amp;qid=&amp;seller=&amp;sr=">&nbsp;Used&nbsp;<span class="numberreturned"></span>&nbsp;</a>
        //            </td>

        //        <td class="olprightoff">&nbsp;&nbsp;</td>
        //    </tr>
        //</table>

        //HtmlNode newANode = rootNode.SelectSingleNode("//td[@id='new' and @class='olpmiddleoffonleft']/a[@href]");
        HtmlNode newANode = rootNode.SelectSingleNode("//td[@id='new' and contains(@class, 'olpmiddle')]/a[@href]"); //olpmiddleoffonleft or olpmiddleon inactive

        if (newANode == null)
        {
            //http://www.amazon.com/gp/offer-listing/B0005YWH7A/ref=dp_olp_new_mbc?ie=UTF8&condition=new
            //<ul id='olpTabs' class='a-tabs'>
            //    <li id='olpTabAll'><a href='/gp/offer-listing/B0005YWH7A/sr=/qid=/ref=olp_tab_all?ie=UTF8&colid=&coliid=&me=&qid=&seller=&sr='>All</a></li>
            //    <li id='olpTabNew' class='a-active'><a href='/gp/offer-listing/B0005YWH7A/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr='>&nbsp;New&nbsp;<span class="numberreturned">from $32.99</span>&nbsp;<span class="olpPercentOff">(Save  <b>18</b>%)</span></a></li>
            //</ul>

            //http://www.amazon.com/gp/offer-listing/B00A8UT558
            //<ul id='olpTabs' class='a-tabs'>
            //    <li id='olpTabAll' class='a-active'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_all?ie=UTF8&colid=&coliid=&me=&qid=&seller=&sr='>All</a></li>
            //    <li id='olpTabNew'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr='>New from $13.99 (Save  <b>6</b>%)</a></li>
            //    <li id='olpTabUsed'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr='>Used  </a></li>
            //</ul>
            
            newANode = rootNode.SelectSingleNode("//li[@id='olpTabNew']/a[@href]"); //olpmiddleoffonleft or olpmiddleon inactive
        }

        if (newANode != null)
        {
            string newAHref = newANode.Attributes["href"].Value; // "/gp/offer-listing/B007OZNZG0/sr=/qid=/ref=olp_tab_new?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;seller=&amp;sr="
            string rawNewAUrl = constAmazonDomainUrl + newAHref; // "http://www.amazon.com/gp/offer-listing/B007OZNZG0/sr=/qid=/ref=olp_tab_new?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;seller=&amp;sr="
            string newAUrl = HttpUtility.HtmlDecode(rawNewAUrl); // "http://www.amazon.com/gp/offer-listing/B007OZNZG0/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr="

            singleTypeAllSellerInfoList = extractAllSingleTypeSellerInfo(newAUrl);
            allSellerInfoList.AddRange(singleTypeAllSellerInfoList);

            extractSellerInfoOk = true;
        }
        else
        {
            //something wrong ?
            extractSellerInfoOk = false;
            gLogger.Debug("not found newANode for " + usedAndNewUrl);
        }

        //HtmlNode usedANode = rootNode.SelectSingleNode("//td[@id='used' and @class='olpmiddleoff']/a[@href]");
        HtmlNode usedANode = null;
        if (usedANode == null)
        {
            usedANode = rootNode.SelectSingleNode("//td[@id='used' and contains(@class, 'olpmiddleoff')]/a[@href]");//olpmiddleoff or olpmiddleoffonleft
        }

        if (usedANode == null)
        {            
            //http://www.amazon.com/gp/offer-listing/B00A8UT558
            //<ul id='olpTabs' class='a-tabs'>
            //    <li id='olpTabAll' class='a-active'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_all?ie=UTF8&colid=&coliid=&me=&qid=&seller=&sr='>All</a></li>
            //    <li id='olpTabNew'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_new?ie=UTF8&colid=&coliid=&condition=new&me=&qid=&seller=&sr='>New from $13.99 (Save  <b>6</b>%)</a></li>
            //    <li id='olpTabUsed'><a href='/gp/offer-listing/B00A8UT558/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr='>Used  </a></li>
            //</ul>
            usedANode = rootNode.SelectSingleNode("//li[@id='olpTabUsed']/a[@href]");
        }

        if (usedANode != null)
        {
            string usedAHref = usedANode.Attributes["href"].Value;
            string rawUsedAUrl = constAmazonDomainUrl + usedAHref;
            string usedAUrl = HttpUtility.HtmlDecode(rawUsedAUrl); //"http://www.amazon.com/gp/offer-listing/B007OZNZG0/sr=/qid=/ref=olp_tab_used?ie=UTF8&colid=&coliid=&condition=used&me=&qid=&seller=&sr="

            singleTypeAllSellerInfoList = extractAllSingleTypeSellerInfo(usedAUrl);
            allSellerInfoList.AddRange(singleTypeAllSellerInfoList);

            extractSellerInfoOk = true;
        }
        else
        {
            //something wrong ?

            //or special:

            //http://www.amazon.com/gp/offer-listing/B003B3OOPA/ref=dp_olp_new_mbc?ie=UTF8&condition=new
            //<table id="metatabs" cellspacing="0">
            //    <tr id="metatabrow">
            //            <td id="all" class="olpleftoff">
            //                <a href="/gp/offer-listing/B003B3OOPA/sr=/qid=/ref=olp_tab_all?ie=UTF8&amp;colid=&amp;coliid=&amp;me=&amp;qid=&amp;seller=&amp;sr=">All</a>
            //            </td>
            //            <td id="new" class="olpmiddleon inactive">
            //                <a href="/gp/offer-listing/B003B3OOPA/sr=/qid=/ref=olp_tab_new?ie=UTF8&amp;colid=&amp;coliid=&amp;condition=new&amp;me=&amp;qid=&amp;seller=&amp;sr=">&nbsp;New&nbsp;<span class="numberreturned">from $8.09</span>&nbsp;<span class="olpPercentOff">(Save  <b>8</b>%)</span></a>
            //            </td>

            //        <td class="olprighton">&nbsp;&nbsp;</td>
            //    </tr>
            //</table>


            //special:
            //http://www.amazon.com/gp/offer-listing/B001FA1L9I/sr=/qid=/ref=olp_tab_all?ie=UTF8&colid=&coliid=&me=&qid=&seller=&sr=
            // no used

            if (extractSellerInfoOk)
            {
                //not overwrite previous, has got newANode
            }
            else
            {
                extractSellerInfoOk = false;
            }
            
            gLogger.Debug("not found usedANode for " + usedAndNewUrl);
        }

        return extractSellerInfoOk;
    }

    /*
     * [Function]
     * extract product keyword filed, total 3 string, each <= 50 chars
     * [Input]
     * amazon product title
     * "GE MWF Refrigerator Water Filter, 1-Pack"
     * [Output]
     * 3 keyword field
     * "GE MWF Refrigerator Water Filter, 1-Pack"
     * [Note]
     */
    public string[] extractProductKeywordField(string productTitle, int keywordFieldArrLen, int maxSingleKeywordFieldLen)
    {
        string[] keywordFieldArr = new string[keywordFieldArrLen];
        crl.emptyStringArray(keywordFieldArr);

        if(productTitle != "")
        {
            string noCommarTitle = productTitle.Replace(",", "");
            string[] wordList = noCommarTitle.Split();
            //[0]	"GE"	string
            //[1]	"MWF"	string
            //[2]	"Refrigerator"	string
            //[3]	"Water"	string
            //[4]	"Filter"	string
            //[5]	"1-Pack"	string
                        
            string curKeywordFieldStr = "";
            int curKeywordkFieldIdx = 0;
            for (int idx = 0; idx < wordList.Length; idx++)
            {
                string singleWord = wordList[idx];
                string oldKeywordFieldStr = curKeywordFieldStr;
                string newKeywordFieldStr;
                if (curKeywordFieldStr == "")
                {
                    newKeywordFieldStr = curKeywordFieldStr + singleWord;
                }
                else
                {
                    newKeywordFieldStr = curKeywordFieldStr + "," + singleWord;
                }
                
                if ((oldKeywordFieldStr.Length < maxSingleKeywordFieldLen) && (newKeywordFieldStr.Length >= maxSingleKeywordFieldLen))
                {
                    keywordFieldArr[curKeywordkFieldIdx] = curKeywordFieldStr;
                    ++curKeywordkFieldIdx;

                    if (idx >= keywordFieldArrLen)
                    {
                        //done
                        break;
                    }
                }
                else if(newKeywordFieldStr.Length < maxSingleKeywordFieldLen)
                {
                    curKeywordFieldStr = newKeywordFieldStr;

                    keywordFieldArr[curKeywordkFieldIdx] = curKeywordFieldStr;
                }
            }
        }

        return keywordFieldArr;
    }

    /*
     * [Function]
     * extract customer reviews number from product html
     * [Input]
     * amazon product url's html
     * [Output]
     * product customer reviews number
     * [Note]
     */
    public int extractProductReviewNumber(string productUrl = "", string productHtml = "")
    {
        int reviewNumber = 0;

        //if not give html, get it
        if (string.IsNullOrEmpty(productHtml))
        {
            productHtml = crl.getUrlRespHtml_multiTry(productUrl);
        }

        //http://www.amazon.com/Silver-Linings-Playbook/dp/B00CL68QVQ/ref=sr_1_2?s=instant-video&ie=UTF8&qid=1368688342&sr=1-2
        //<span class="tiny">
            //<span class="crAvgStars" style="white-space:no-wrap;">
            //    <span class="asinReviewsSummary acr-popover" name="B00CL68QVQ" ref="dp_top_cm_cr_acr_txt_cm_cr_acr_pop_" >......</span>
            //    (
            //<a href="http://www.amazon.com/Silver-Linings-Playbook/product-reviews/B00CL68QVQ/ref=dp_top_cm_cr_acr_txt_cm_cr_acr_txt?ie=UTF8&showViewpoints=1" >
            //        925 customer reviews
            //    </a>
            //    )
            //</span>

        //special:
        //http://www.amazon.com/Sony-MDR-ZX100-Series-Headphones-White/dp/B004RKQM8I/ref=lp_1055398_1_22?ie=UTF8&qid=1370527505&sr=1-22
        //has first "Similar Item with Better Ratings", it also contains reviews
        //real one is:
        //<span class="stars">
        //    ......
        //    <span class="crAvgStars" style="white-space:no-wrap;">
        //    <span class="asinReviewsSummary acr-popover" name="B00CL68QVQ" ref="dp_top_cm_cr_acr_txt_cm_cr_acr_pop_" >......</span>(<a href="http://www.amazon.com/Silver-Linings-Playbook/product-reviews/B00CL68QVQ/ref=dp_top_cm_cr_acr_txt_cm_cr_acr_txt?ie=UTF8&showViewpoints=1" >925 customer reviews</a>)</span>
        //</span>

        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(productHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;
        //HtmlNode avgStarANode = rootNode.SelectSingleNode("//span[@class='crAvgStars']/a");
        HtmlNode avgStarANode = rootNode.SelectSingleNode("//span[@class]/span[@class='crAvgStars']/a");
        if (avgStarANode != null)
        {
            string customerReviewsStr = avgStarANode.InnerText; //"12,184 customer reviews"
            string reviewNumberStr = "";
            if (crl.extractSingleStr(@"([\d,]+) customer reviews", customerReviewsStr, out reviewNumberStr))
            {
                reviewNumberStr = reviewNumberStr.Replace(",", "");//12184
                reviewNumber = Int32.Parse(reviewNumberStr);
            }
            else 
            {
                //something wrong

                //special:
                //http://www.amazon.com/gp/product/B005SSWKMK
                //<div class='fl mt15 clearboth'>
                //<a id='revSAR' href='http://www.amazon.com/Casio-PRW2500T-7CR-Pathfinder-Multi-Function-Titanium/product-reviews/B005SSWKMK/ref=cm_cr_dp_see_all_summary?ie=UTF8&showViewpoints=1' class='txtsmall noTextDecoration'>
                //    See all 89 customer reviews
                //</a>
                //</div>
                HtmlNode revSarANode = rootNode.SelectSingleNode("//a[@id='revSAR']");
                if (revSarANode != null)
                {
                    string strSeeAll = revSarANode.InnerText; //"      See all 89 customer reviews    "
                    strSeeAll = strSeeAll.Trim();
                    string strSeeAllCustomerReviews = "";
                    if (crl.extractSingleStr(@"see all ([\d,]+) customer reviews", strSeeAll, out strSeeAllCustomerReviews, RegexOptions.IgnoreCase))
                    {
                        strSeeAllCustomerReviews = strSeeAllCustomerReviews.Replace(",", ""); //"89"
                        reviewNumber = Int32.Parse(strSeeAllCustomerReviews);
                    }
                }
                else 
                {
                    //something wrong
                    gLogger.Debug("can not found See all xxx customer reviews");
                }
            }
        }
        else
        {
            //something wrong ?
        }
        return reviewNumber;
    }

    /*
     * [Function]
     * extract product best seller rank number list from product html
     * [Input]
     * amazon product url or its html
     * [Output]
     * best seller rank number list
     * [Note]
     */
    public List<productBestRank> extractProductBestSellerRankList(string productUrl = "", string productHtml = "")
    {
        List<productBestRank> bestSellerRankList = new List<productBestRank>();

        //if not give html, get it
        if (string.IsNullOrEmpty(productHtml))
        {
            productHtml = crl.getUrlRespHtml_multiTry(productUrl);
        }

        //special:
        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_1?ie=UTF8&qid=1370531997&sr=1-1
        //http://www.amazon.com/Intex-Pillow-Airbed-Built--Electric/dp/B000HBILB2/ref=lp_1055398_1_24?ie=UTF8&qid=1370531997&sr=1-24
        //no best seller rank

        //http://www.amazon.com/Sony-MDR-ZX100-Series-Headphones-White/dp/B004RKQM8I/ref=lp_1055398_1_22?ie=UTF8&qid=1370527505&sr=1-22
        //<li id="SalesRank">
        //<b>Amazon Best Sellers Rank:</b> 
        //......
        //<ul class="zg_hrsr">
        //    <li class="zg_hrsr_item">
        //        <span class="zg_hrsr_rank">#3</span> 
        //        <span class="zg_hrsr_ladder">in&nbsp;<a href="http://www.amazon.com/gp/bestsellers/electronics/ref=pd_zg_hrsr_e_1_1">Electronics</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/electronics/281407/ref=pd_zg_hrsr_e_1_2">Accessories & Supplies</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/electronics/172532/ref=pd_zg_hrsr_e_1_3">Audio & Video Accessories</a> &gt; <b><a href="http://www.amazon.com/gp/bestsellers/electronics/172541/ref=pd_zg_hrsr_e_1_4_last">Headphones</a></b></span>
        //    </li>
        //    <li class="zg_hrsr_item">
        //        <span class="zg_hrsr_rank">#4</span> 
        //        <span class="zg_hrsr_ladder">in&nbsp;<a href="http://www.amazon.com/gp/bestsellers/electronics/ref=pd_zg_hrsr_e_2_1">Electronics</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/electronics/541966/ref=pd_zg_hrsr_e_2_2">Computers & Add-Ons</a> &gt; <b><a href="http://www.amazon.com/gp/bestsellers/electronics/193870011/ref=pd_zg_hrsr_e_2_3_last">Computer Components</a></b></span>
        //    </li>
        //    <li class="zg_hrsr_item">
        //        <span class="zg_hrsr_rank">#9</span> 
        //        <span class="zg_hrsr_ladder">in&nbsp;<a href="http://www.amazon.com/gp/bestsellers/electronics/ref=pd_zg_hrsr_e_3_1">Electronics</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/electronics/172623/ref=pd_zg_hrsr_e_3_2">Portable Audio & Video</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/electronics/172630/ref=pd_zg_hrsr_e_3_3">MP3 Players & Accessories</a> &gt; <b><a href="http://www.amazon.com/gp/bestsellers/electronics/290438/ref=pd_zg_hrsr_e_3_4_last">MP3 Player Accessories</a></b></span>
        //    </li>
        //</ul>
        //</li>

        //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_9?ie=UTF8&qid=1370531997&sr=1-9
        //<tr id="SalesRank">
        //    <td class="label">Best Sellers Rank</td>
        //    <td class="value">
        //        #3 in Home Improvement (<a href="http://www.amazon.com/gp/bestsellers/hi/ref=pd_dp_ts_hi_1">See top 100</a>)
        //        <ul class="zg_hrsr">
        //            <li class="zg_hrsr_item">
        //            <span class="zg_hrsr_rank">#1</span> 
        //            <span class="zg_hrsr_ladder">in&nbsp;<a href="http://www.amazon.com/gp/bestsellers/hi/ref=pd_zg_hrsr_hi_1_1">Home Improvement</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/3754161/ref=pd_zg_hrsr_hi_1_2">Kitchen & Bath Fixtures</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/13397631/ref=pd_zg_hrsr_hi_1_3">Water Filtration & Softeners</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/680337011/ref=pd_zg_hrsr_hi_1_4_last">Faucet Water Filters</a></span>
        //            </li>
        //            <li class="zg_hrsr_item">
        //            <span class="zg_hrsr_rank">#2</span> 
        //            <span class="zg_hrsr_ladder">in&nbsp;<a href="http://www.amazon.com/gp/bestsellers/hi/ref=pd_zg_hrsr_hi_2_1">Home Improvement</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/13397451/ref=pd_zg_hrsr_hi_2_2">Appliances</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/3741181/ref=pd_zg_hrsr_hi_2_3">Large Appliance Accessories</a> &gt; <a href="http://www.amazon.com/gp/bestsellers/hi/3741241/ref=pd_zg_hrsr_hi_2_4_last">Refrigerator Parts & Accessories</a></span>
        //            </li>
        //        </ul>
        //    </td>
        //</tr>


        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(productHtml);
        //HtmlNode salesRankNode = htmlDoc.DocumentNode.SelectSingleNode("//li[@id='SalesRank']");
        //HtmlNode salesRankNode = htmlDoc.DocumentNode.SelectSingleNode("//(li|tr)[@id='SalesRank']");
        HtmlNode salesRankNode = htmlDoc.DocumentNode.SelectSingleNode("//*[self::li|self::tr][@id='SalesRank']");
        if (salesRankNode != null)
        {
            //check if exist: <td class="value">
            //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_9?ie=UTF8&qid=1370531997&sr=1-9
            //http://www.amazon.com/Thermos-Insulated-18-Ounce-Stainless-Steel-Hydration/dp/B000FJ9DOK/ref=lp_1055398_1_6?ie=UTF8&qid=1370574186&sr=1-6
            HtmlNode tdClassValueNode = salesRankNode.SelectSingleNode("./td[@class='value']");
            if (tdClassValueNode != null)
            {
                //check whether match following
                //#3 in Home Improvement (<a href="http://www.amazon.com/gp/bestsellers/hi/ref=pd_dp_ts_hi_1">See top 100</a>)
                string tdClassValueHtml = tdClassValueNode.InnerHtml;//"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n#3 in Home Improvement (<a href=\"http://www.amazon.com/gp/bestsellers/hi/ref=pd_dp_ts_hi_1\">See top 100</a>)\n  \n\n\n\n\n\n\n \n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n<ul class=\"zg_hrsr\">\n    <li class=\"zg_hrsr_item\">\n    <span class=\"zg_hrsr_rank\">#1</span> \n    <span class=\"zg_hrsr_ladder\">in&nbsp;<a href=\"http://www.amazon.com/gp/bestsellers/hi/ref=pd_zg_hrsr_hi_1_1\">Home Improvement</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/3754161/ref=pd_zg_hrsr_hi_1_2\">Kitchen & Bath Fixtures</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/13397631/ref=pd_zg_hrsr_hi_1_3\">Water Filtration & Softeners</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/680337011/ref=pd_zg_hrsr_hi_1_4_last\">Faucet Water Filters</a></span>\n    </li>\n    <li class=\"zg_hrsr_item\">\n    <span class=\"zg_hrsr_rank\">#2</span> \n    <span class=\"zg_hrsr_ladder\">in&nbsp;<a href=\"http://www.amazon.com/gp/bestsellers/hi/ref=pd_zg_hrsr_hi_2_1\">Home Improvement</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/13397451/ref=pd_zg_hrsr_hi_2_2\">Appliances</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/3741181/ref=pd_zg_hrsr_hi_2_3\">Large Appliance Accessories</a> &gt; <a href=\"http://www.amazon.com/gp/bestsellers/hi/3741241/ref=pd_zg_hrsr_hi_2_4_last\">Refrigerator Parts & Accessories</a></span>\n    </li>\n</ul>\n\n\n\n\n"
                //Regex firstRankItemRx = new Regex(@"#(?<rankNumStr>\d+)\sin\s(?<categoryStr>.+?)\s\(<a\shref=""[^""]+?"">.+?</a>\)");
                //#1,663 in Home Improvement (<a href=\"http://www.amazon.com/gp/bestsellers/hi/ref=pd_dp_ts_hi_1\">See top 100</a>)
                Regex firstRankItemRx = new Regex(@"#(?<rankNumStr>[\d,]+)\sin\s(?<categoryStr>.+?)\s\(<a\shref=""[^""]+?"">.+?</a>\)");
                Match foundFirstRankItem = firstRankItemRx.Match(tdClassValueHtml);
                if (foundFirstRankItem.Success)
                {
                    string rankNumStr = foundFirstRankItem.Groups["rankNumStr"].Value; //1,663
                    string categoryStr = foundFirstRankItem.Groups["categoryStr"].Value;

                    productBestRank bestRankItem = new productBestRank();
                    rankNumStr = rankNumStr.Replace(",", ""); //1663
                    bestRankItem.rankNumber = Int32.Parse(rankNumStr);
                    bestRankItem.categoryList = new List<categoryInfo>();

                    categoryInfo curCategoryInfo = new categoryInfo();
                    curCategoryInfo.name = HttpUtility.HtmlDecode(categoryStr);
                    curCategoryInfo.link = "";
                    bestRankItem.categoryList.Add(curCategoryInfo);

                    bestSellerRankList.Add(bestRankItem);
                }
                else
                {
                    //something wrong
                    gLogger.Debug("can not find foundFirstRankItem");
                }
            }

            HtmlNodeCollection hrsrItemNodeList = salesRankNode.SelectNodes(".//ul[@class='zg_hrsr']/li[@class='zg_hrsr_item']");
            if ((hrsrItemNodeList != null) && (hrsrItemNodeList.Count > 0))
            {
                foreach (HtmlNode hrsrItemNode in hrsrItemNodeList)
                {
                    productBestRank bestRankItem = new productBestRank();
                    bestRankItem.rankNumber = 0;
                    bestRankItem.categoryList = new List<categoryInfo>();

                    HtmlNode rankNode = hrsrItemNode.SelectSingleNode(".//span[@class='zg_hrsr_rank']");
                    if (rankNode != null)
                    {
                        string rankNumStr = rankNode.InnerText; //#3
                        rankNumStr = rankNumStr.Replace("#", "");
                        int rankNumInt = Int32.Parse(rankNumStr);
                        bestRankItem.rankNumber = rankNumInt;
                    }
                    else
                    {
                        //something wrong
                    }

                    HtmlNode ladderNode = hrsrItemNode.SelectSingleNode(".//span[@class='zg_hrsr_ladder']");
                    if (ladderNode != null)
                    {
                        HtmlNodeCollection categoryNodeList = ladderNode.SelectNodes(".//a[@href]");
                        if ((categoryNodeList != null) && (categoryNodeList.Count > 0))
                        {
                            foreach (HtmlNode categoryNode in categoryNodeList)
                            {
                                categoryInfo curCategoryInfo = new categoryInfo();
                                curCategoryInfo.link = HttpUtility.HtmlDecode(categoryNode.Attributes["href"].Value);
                                curCategoryInfo.name = HttpUtility.HtmlDecode(categoryNode.InnerText);
                                bestRankItem.categoryList.Add(curCategoryInfo);
                            }
                        }
                        else
                        {
                            //something wrong
                        }
                    }
                    else
                    {
                        //something wrong
                    }

                    bestSellerRankList.Add(bestRankItem);
                }
            }
        }
        else
        {
            //something wrong
        }

        return bestSellerRankList;
    }

    /*
     * [Function]
     * extract weight from product html
     * [Input]
     * amazon product url's html
     * [Output]
     * product weight, in kilogram
     * if not found, return -1.0
     * [Note]
     */
    public float extractProductWeight(string productHtml)
    {
        bool calculatedKiloGram = false;
        float kiloGram = -1.0F;
        string weightNumberStr = "";
        
        //type1:
        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1369487181&sr=1-1
        //<td style="font-weight: bold;text-align:left; font-size: 12px; border-bottom: 1px solid #e2e2e2;" align="right">Weight</td><td style="font-size:12px;">13.9 ounces (395 grams)</td>
        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_2?ie=UTF8&qid=1369487181&sr=1-2
        //<td style="font-weight: bold;text-align:left; font-size: 12px; border-bottom: 1px solid #e2e2e2;" align="right">Weight</td><td style="font-size:12px;">7.5 ounces (213 grams)</td>
        if (!calculatedKiloGram)
        {
            if (crl.extractSingleStr(@"Weight</td><td style=""[^<>]+?"">([\.\d]+) ounces", productHtml, out weightNumberStr))
            {
                float onces = float.Parse(weightNumberStr);
                kiloGram = crl.ounceToKiloGram(onces);

                calculatedKiloGram = true;
            }
            else
            {
                //not find this kind of weight string
            }
        }

        //type2:
        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_3?ie=UTF8&qid=1369487181&sr=1-3
        //<td class="label">Item Weight</td><td class="value">6.4 ounces</td>
        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1369487181&sr=1-4
        //<td class="label">Item Weight</td><td class="value">12.8 ounces</td>
        //http://www.amazon.com/Samsung-Galaxy-Tab-10-1-Inch-Wi-Fi/dp/B007M50PTM/ref=lp_1055398_1_21?ie=UTF8&qid=1369492830&sr=1-21
        //<td class="label">Item Weight</td><td class="value">1.3 pounds</td>
        if (!calculatedKiloGram)
        {
            Regex rx = new Regex(@"<td class=""label"">Item Weight</td><td class=""value"">(?<weightNumber>[\.\d]+) (?<unitType>(ounces)|(pounds))");
            Match foundWeight = rx.Match(productHtml);
            if (foundWeight.Success)
            {
                weightNumberStr = foundWeight.Groups["weightNumber"].Value;
                string unitType = foundWeight.Groups["unitType"].Value;
                if (unitType.Equals("ounces"))
                {
                    float onces = float.Parse(weightNumberStr);
                    kiloGram = crl.ounceToKiloGram(onces);
                }
                else if (unitType.Equals("pounds"))
                {
                    float pound = float.Parse(weightNumberStr);
                    kiloGram = crl.poundToKiloGram(pound);
                }
                else
                {
                    //some unsupported weight unit
                }
            }
            else
            {
                //not find this kind of weight string
            }
        }

        //type3:
        //http://www.amazon.com/San-Francisco-Bay-Coffee-80-Count/dp/B007Y59HVM/ref=lp_1055398_1_5?ie=UTF8&qid=1369487181&sr=1-5
        //<b>Shipping Weight:</b> 3.3 pounds (<a href="http://www.amazon.com/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B007Y59HVM&amp;seller=">View shipping rates and policies</a>)
        //http://www.amazon.com/Glad-Kitchen-Drawstring-Garbage-Gallon/dp/B005GSYXHW/ref=lp_1055398_1_7?ie=UTF8&qid=1369487181&sr=1-7
        //<b>Shipping Weight:</b> 2.2 pounds (<a href="http://www.amazon.com/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B005GSYXHW&amp;seller=">View shipping rates and policies</a>)
        //http://www.amazon.com/Brooklyn-Beans-Variety-Coffee-Brewers/dp/B008I1XPKA/ref=lp_1055398_1_8?ie=UTF8&qid=1369487181&sr=1-8
        //<b>Shipping Weight:</b> 1.4 pounds (<a href="http://www.amazon.com/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B008I1XPKA&amp;seller=ATVPDKIKX0DER">View shipping rates and policies</a>)
        //http://www.amazon.com/RID-X-Septic-System-Treatment-1-Dose/dp/B000PINS38/ref=lp_1055398_1_24?ie=UTF8&qid=1369494305&sr=1-24
        //<b>Shipping Weight:</b> 12.3 ounces (<a href="http://www.amazon.com/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B000PINS38&amp;seller=ATVPDKIKX0DER">View shipping rates and policies</a>)
        if (!calculatedKiloGram)
        {
            Regex rx = new Regex(@"<b>Shipping Weight:</b> (?<weightNumber>[\.\d]+) (?<unitType>(ounces)|(pounds))");
            Match foundWeight = rx.Match(productHtml);
            if (foundWeight.Success)
            {
                weightNumberStr = foundWeight.Groups["weightNumber"].Value;
                string unitType = foundWeight.Groups["unitType"].Value;
                if (unitType.Equals("ounces"))
                {
                    float onces = float.Parse(weightNumberStr);
                    kiloGram = crl.ounceToKiloGram(onces);
                }
                else if (unitType.Equals("pounds"))
                {
                    float pound = float.Parse(weightNumberStr);
                    kiloGram = crl.poundToKiloGram(pound);
                }
                else
                {
                    //some unsupported weight unit
                }
            }
            else
            {
                //not find this kind of weight string
            }
        }

        //type4:
        //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_6?ie=UTF8&qid=1369487181&sr=1-6
        //<td class="label">Shipping Weight</td><td class="value">8.8 ounces (<a href="http://www.amazon.com/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B001XW8KW4&amp;seller=ATVPDKIKX0DER">View shipping rates and policies</a>)</td>
        //http://www.amazon.com/Frigidaire-FAD704DUD-70-Pt-Dehumidifier/dp/B004TB29O6/ref=sr_1_69?s=home-garden&ie=UTF8&qid=1369496509&sr=1-69
        //<td class="label">Shipping Weight</td><td class="value">46 pounds (<a href="/gp/help/seller/shipping.html/ref=dp_pd_shipping?ie=UTF8&amp;asin=B004TB29O6&amp;seller=ATVPDKIKX0DER">View shipping rates and policies</a>)</td>
        if (!calculatedKiloGram)
        {
            Regex rx = new Regex(@"<td class=""label"">Shipping Weight</td><td class=""value"">(?<weightNumber>[\.\d]+) (?<unitType>(ounces)|(pounds))");
            Match foundWeight = rx.Match(productHtml);
            if (foundWeight.Success)
            {
                weightNumberStr = foundWeight.Groups["weightNumber"].Value;
                string unitType = foundWeight.Groups["unitType"].Value;
                if (unitType.Equals("ounces"))
                {
                    float onces = float.Parse(weightNumberStr);
                    kiloGram = crl.ounceToKiloGram(onces);
                }
                else if (unitType.Equals("pounds"))
                {
                    float pound = float.Parse(weightNumberStr);
                    kiloGram = crl.poundToKiloGram(pound);
                }
                else
                {
                    //some unsupported weight unit
                }
            }
            else
            {
                //not find this kind of weight string
            }
        }

        //type5:
        //http://www.amazon.com/Coleman-9949-750-Road-Trip-Grill/dp/B0009V1BDA/ref=sr_1_189?s=home-garden&ie=UTF8&qid=1369497854&sr=1-189
        //The collapsed grill measures 36 by 22 by 13 inches with a shipping weight of 60 pounds; limited 5-year warranty
        if (!calculatedKiloGram)
        {
            Regex rx = new Regex(@"with a shipping weight of (?<weightNumber>[\.\d]+) (?<unitType>(ounces)|(pounds))", RegexOptions.IgnoreCase);
            Match foundWeight = rx.Match(productHtml);
            if (foundWeight.Success)
            {
                weightNumberStr = foundWeight.Groups["weightNumber"].Value;
                string unitType = foundWeight.Groups["unitType"].Value;
                if (unitType.Equals("ounces"))
                {
                    float onces = float.Parse(weightNumberStr);
                    kiloGram = crl.ounceToKiloGram(onces);
                }
                else if (unitType.Equals("pounds"))
                {
                    float pound = float.Parse(weightNumberStr);
                    kiloGram = crl.poundToKiloGram(pound);
                }
                else
                {
                    //some unsupported weight unit
                }
            }
            else
            {
                //not find this kind of weight string
            }
        }

        return kiloGram;
    }

    /*
     * [Function]
     * extract dimension from product html
     * [Input]
     * amazon product url's html
     * [Output]
     * product dimension, in cm
     * if not found, return 0
     * [Note]
     */
    public productDimension extractProductDimension(string productHtml)
    {
        bool foundDimensionStr = false;

        productDimension dimensionCm = new productDimension();
        dimensionCm.length = -1.0F;
        dimensionCm.width = -1.0F;
        dimensionCm.height = -1.0F;

        productDimension dimensionInch = new productDimension();
        dimensionInch.length = -1.0F;
        dimensionInch.width = -1.0F;
        dimensionInch.height = -1.0F;

        string lengthInchStr = "";
        string widthInchStr = "";
        string heightInchStr = ""; ;
        //string dimensionStr = "";

        //type1:
        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1369487181&sr=1-1
        //<td align="right" style="font-weight: bold;text-align:left; font-size: 12px; border-bottom: 1px solid #e2e2e2;">Size</td><td style="font-size:12px;">7.6" x 5.4" x 0.4" (193 mm x 137 mm x 10.3 mm)</td>
        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_2?ie=UTF8&qid=1369487181&sr=1-2
        //<td style="font-weight: bold;text-align:left; font-size: 12px; border-bottom: 1px solid #e2e2e2;" align="right">Size</td><td style="font-size:12px;">6.7" x 4.6" x 0.36" (169 mm x 117 mm x 9.1 mm)</td>
        if (!foundDimensionStr)
        {
            Regex rx = new Regex(@"Size</td><td style=""[^<>]+?"">(?<lengthStr>[\d\.]+)""? x (?<widthStr>[\d\.]+)""? x (?<heightStr>[\d\.]+)""?( inches)?");
            Match foundDimension = rx.Match(productHtml);
            if (foundDimension.Success)
            {
                lengthInchStr = foundDimension.Groups["lengthStr"].Value;
                widthInchStr = foundDimension.Groups["widthStr"].Value;
                heightInchStr = foundDimension.Groups["heightStr"].Value;

                foundDimensionStr = true;
            }
            else
            {
                //not find this kind of dimension string
            }
        }

        //type2:
        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_3?ie=UTF8&qid=1369487181&sr=1-3
        //<td class="label">Product Dimensions</td><td class="value">0.7 x 5.5 x 3.4 inches</td>
        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1369487181&sr=1-4
        //<td class="label">Product Dimensions</td><td class="value">3 x 3 x 5 inches</td>
        //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_6?ie=UTF8&qid=1369487181&sr=1-6
        //<td class="label">Product Dimensions</td><td class="value">8.1 x 2.4 x 2.4 inches</td>
        //http://www.amazon.com/Frigidaire-FAD704DUD-70-Pt-Dehumidifier/dp/B004TB29O6/ref=sr_1_69?s=home-garden&ie=UTF8&qid=1369496509&sr=1-69
        //<td class="label">Product Dimensions</td><td class="value">11.3 x 16.1 x 24.6 inches</td>
        if (!foundDimensionStr)
        {
            Regex rx = new Regex(@"<td class=""label"">Product Dimensions</td><td class=""value"">(?<lengthStr>[\d\.]+) x (?<widthStr>[\d\.]+) x (?<heightStr>[\d\.]+) inches</td>");
            Match foundDimension = rx.Match(productHtml);
            if (foundDimension.Success)
            {
                lengthInchStr = foundDimension.Groups["lengthStr"].Value;
                widthInchStr = foundDimension.Groups["widthStr"].Value;
                heightInchStr = foundDimension.Groups["heightStr"].Value;

                foundDimensionStr = true;
            }
            else
            {
                //not find this kind of dimension string
            }
        }

        //type3:
        //http://www.amazon.com/Glad-Kitchen-Drawstring-Garbage-Gallon/dp/B005GSYXHW/ref=lp_1055398_1_7?ie=UTF8&qid=1369487181&sr=1-7
        //<b>
        //Product Dimensions: 
        //</b>
        //8.4 x 4.5 x 4.6 inches ; 2.2 pounds
        //http://www.amazon.com/RID-X-Septic-System-Treatment-1-Dose/dp/B000PINS38/ref=lp_1055398_1_24?ie=UTF8&qid=1369494305&sr=1-24
        //Product Dimensions: 
        //</b>
        //1.4 x 4.2 x 8 inches ; 11.7 ounces
        //http://www.amazon.com/Cuisinart-CGG-180-Gourmet-Portable-VersaStand/dp/B004H4WW9W/ref=pd_sbs_hg_5
        //Product Dimensions: 
        //</b>
        //12 x 30 x 31 inches ; 23.5 pounds
        if (!foundDimensionStr)
        {
            Regex rx = new Regex(@"<b>\s*Product Dimensions:\s*</b>\s*(?<lengthStr>[\d\.]+) x (?<widthStr>[\d\.]+) x (?<heightStr>[\d\.]+) inches");
            Match foundDimension = rx.Match(productHtml);
            if (foundDimension.Success)
            {
                lengthInchStr = foundDimension.Groups["lengthStr"].Value;
                widthInchStr = foundDimension.Groups["widthStr"].Value;
                heightInchStr = foundDimension.Groups["heightStr"].Value;

                foundDimensionStr = true;
            }
            else
            {
                //not find this kind of dimension string
            }
        }

        //type4:
        //http://www.amazon.com/Samsung-Galaxy-Tab-10-1-Inch-Wi-Fi/dp/B007M50PTM/ref=lp_1055398_1_21?ie=UTF8&qid=1369492830&sr=1-21
        //<strong>Dimensions:</strong> 10.1 x 6.9 x 0.38 inches 
        if (!foundDimensionStr)
        {
            Regex rx = new Regex(@"<strong>Dimensions:</strong> (?<lengthStr>[\d\.]+) x (?<widthStr>[\d\.]+) x (?<heightStr>[\d\.]+) inches");
            Match foundDimension = rx.Match(productHtml);
            if (foundDimension.Success)
            {
                lengthInchStr = foundDimension.Groups["lengthStr"].Value;
                widthInchStr = foundDimension.Groups["widthStr"].Value;
                heightInchStr = foundDimension.Groups["heightStr"].Value;

                foundDimensionStr = true;
            }
            else
            {
                //not find this kind of dimension string
            }
        }

        //type5:
        //no found size or dimenson
        //http://www.amazon.com/San-Francisco-Bay-Coffee-80-Count/dp/B007Y59HVM/ref=lp_1055398_1_5?ie=UTF8&qid=1369487181&sr=1-5
        //http://www.amazon.com/Brooklyn-Beans-Variety-Coffee-Brewers/dp/B008I1XPKA/ref=lp_1055398_1_8?ie=UTF8&qid=1369487181&sr=1-8
        //http://www.amazon.com/Coleman-9949-750-Road-Trip-Grill/dp/B0009V1BDA/ref=sr_1_189?s=home-garden&ie=UTF8&qid=1369497854&sr=1-189

        //------ check valid or not ------
        if (foundDimensionStr)
        {
            dimensionInch.length = float.Parse(lengthInchStr);
            dimensionInch.width = float.Parse(widthInchStr);
            dimensionInch.height = float.Parse(heightInchStr);

            dimensionCm.length = crl.inchToCm(dimensionInch.length);
            dimensionCm.width = crl.inchToCm(dimensionInch.width);
            dimensionCm.height = crl.inchToCm(dimensionInch.height);
        }
        else
        {
            //not found
        }

        return dimensionCm;
    }

    /*
     * [Function]
     * from best seller category url, extract category key/alias
     * [Input]
     * http://www.amazon.com/Best-Sellers-Appstore-Android/zgbs/mobile-apps/ref=zg_bs_nav_0
     * http://www.amazon.com/Best-Sellers-Appstore-For-Android/zgbs/mobile-apps/ref=zg_bs_nav_0
     * http://www.amazon.com/Best-Sellers/zgbs/mobile-apps/ref=zg_bs_nav_0
     * 
     * http://www.amazon.com/best-sellers-camera-photo/zgbs/photo/ref=zg_bs_nav_0
     * [Output]
     * mobile-apps
     * 
     * photo
     * [Note]
     */
    public bool extractCatKeyFromBestSellerCatUrl(string bestSellerCategoryUrl, out string categoryKey)
    {
        bool extractKeyOk = false;

        categoryKey = "";

        if (crl.extractSingleStr(@"http://www\.amazon\.com/best-sellers.*?/zgbs/(\w+)(/ref=.+?)?", bestSellerCategoryUrl, out categoryKey, RegexOptions.IgnoreCase))
        {
            categoryKey = categoryKey.ToLower();

            extractKeyOk = true;
        }

        return extractKeyOk;
    }

    /*
     * [Function]
     * from category key, generate the best seller category url
     * [Input]
     * mobile-apps
     * [Output]
     * http://www.amazon.com/best-sellers/zgbs/mobile-apps
     * [Note]
     */
    public string generateBestSellerCategoryUrlFromCategoryKey(string categoryKey)
    {
        string bestSellerCategoryUrl = "";

        //extracted from html:
        //http://www.amazon.com/Best-Sellers-Appstore-Android/zgbs/mobile-apps/ref=zg_bs_nav_0
        //others 3:
        //http://www.amazon.com/Best-Sellers-Appstore-For-Android/zgbs/mobile-apps/ref=zg_bs_nav_0
        //http://www.amazon.com/Best-Sellers/zgbs/mobile-apps/ref=zg_bs_nav_0
        //http://www.amazon.com/best-sellers/zgbs/mobile-apps
        //also work !

        bestSellerCategoryUrl = "http://www.amazon.com/best-sellers/zgbs/" + categoryKey;

        return bestSellerCategoryUrl;
    }

    /*
     * [Function]
     * from amazon Bes Seller url extract category
     * [Input]
     * http://www.amazon.com/Best-Sellers/zgbs/ref=zg_bs_tab
     * http://www.amazon.com/Best-Sellers/zgbs
     * [Output]
     * categoryItem list, contains 35 main category:
     * ...
     * [Note]
     */
    public List<categoryItem> extractBestSellerCategoryList(string amazonBestSellerUrl)
    {
        List<categoryItem> bestSellerCategoryList = new List<categoryItem>();

        //http://www.amazon.com/Best-Sellers/zgbs/ref=zg_bs_tab
          //<ul id="zg_browseRoot">
          //  <li> 
          //   <span class="zg_selected"> Any Department</span>
          //  </li> 
          //  <ul>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Appliances/zgbs/appliances/ref=zg_bs_nav_0'>Appliances</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Appstore-Android/zgbs/mobile-apps/ref=zg_bs_nav_0'>Appstore for Android</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Arts-Crafts-Sewing/zgbs/arts-crafts/ref=zg_bs_nav_0'>Arts, Crafts & Sewing</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Automotive/zgbs/automotive/ref=zg_bs_nav_0'>Automotive</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Baby/zgbs/baby-products/ref=zg_bs_nav_0'>Baby</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Beauty/zgbs/beauty/ref=zg_bs_nav_0'>Beauty</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-books-Amazon/zgbs/books/ref=zg_bs_nav_0'>Books</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-camera-photo/zgbs/photo/ref=zg_bs_nav_0'>Camera &amp; Photo</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Cell-Phones-Accessories/zgbs/wireless/ref=zg_bs_nav_0'>Cell Phones & Accessories</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Clothing/zgbs/apparel/ref=zg_bs_nav_0'>Clothing</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Computers-Accessories/zgbs/pc/ref=zg_bs_nav_0'>Computers & Accessories</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Electronics/zgbs/electronics/ref=zg_bs_nav_0'>Electronics</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Gift-Cards-Store/zgbs/gift-cards/ref=zg_bs_nav_0'>Gift Cards Store</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Grocery-Gourmet-Food/zgbs/grocery/ref=zg_bs_nav_0'>Grocery & Gourmet Food</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Health-Personal-Care/zgbs/hpc/ref=zg_bs_nav_0'>Health & Personal Care</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Home-Kitchen/zgbs/home-garden/ref=zg_bs_nav_0'>Home &amp; Kitchen</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Home-Improvement/zgbs/hi/ref=zg_bs_nav_0'>Home Improvement</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Industrial-Scientific/zgbs/industrial/ref=zg_bs_nav_0'>Industrial & Scientific</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Jewelry/zgbs/jewelry/ref=zg_bs_nav_0'>Jewelry</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Kindle-Store/zgbs/digital-text/ref=zg_bs_nav_0'>Kindle Store</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Kitchen-Dining/zgbs/kitchen/ref=zg_bs_nav_0'>Kitchen & Dining</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-MP3-Downloads/zgbs/dmusic/ref=zg_bs_nav_0'>MP3 Downloads</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Magazines/zgbs/magazines/ref=zg_bs_nav_0'>Magazines</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-movies-TV-DVD-Blu-ray/zgbs/movies-tv/ref=zg_bs_nav_0'>Movies & TV</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-music-albums/zgbs/music/ref=zg_bs_nav_0'>Music</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Musical-Instruments/zgbs/musical-instruments/ref=zg_bs_nav_0'>Musical Instruments</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Office-Products/zgbs/office-products/ref=zg_bs_nav_0'>Office Products</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Patio-Lawn-Garden/zgbs/lawn-garden/ref=zg_bs_nav_0'>Patio, Lawn & Garden</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Pet-Supplies/zgbs/pet-supplies/ref=zg_bs_nav_0'>Pet Supplies</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-shoes/zgbs/shoes/ref=zg_bs_nav_0'>Shoes</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-software/zgbs/software/ref=zg_bs_nav_0'>Software</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Sports-Outdoors/zgbs/sporting-goods/ref=zg_bs_nav_0'>Sports &amp; Outdoors</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Toys-Games/zgbs/toys-and-games/ref=zg_bs_nav_0'>Toys &amp; Games</a></li>
          //    <li><a href='http://www.amazon.com/best-sellers-video-games/zgbs/videogames/ref=zg_bs_nav_0'>Video Games</a></li>
          //    <li><a href='http://www.amazon.com/Best-Sellers-Watches/zgbs/watches/ref=zg_bs_nav_0'>Watches</a></li>
          //  </ul>
          //</li></ul>


        string bestSellerHtml = crl.getUrlRespHtml_multiTry(amazonBestSellerUrl);

        HtmlDocument htmlDoc = crl.htmlToHtmlDoc(bestSellerHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;

        HtmlNode browseRootUlNode = rootNode.SelectSingleNode("//ul[@id='zg_browseRoot']/ul");
        if (browseRootUlNode != null)
        {
            //HtmlNodeCollection categoryNodeList = browseRootUlNode.SelectNodes(".//li/a[contains(@href, 'http://www.amazon.com/Best-Sellers-')]");
            //HtmlNodeCollection categoryNodeList = browseRootUlNode.SelectNodes(".//li/a[contains(@href, 'http://www.amazon.com/Best-Sellers-') or contains(@href, 'http://www.amazon.com/best-sellers-')]");
            HtmlNodeCollection categoryNodeList = browseRootUlNode.SelectNodes(".//li/a[contains(@href, 'http://www.amazon.com/')]");

            foreach (HtmlNode categoryNode in categoryNodeList)
            {
                //<li><a href='http://www.amazon.com/best-sellers-camera-photo/zgbs/photo/ref=zg_bs_nav_0'>Camera &amp; Photo</a></li>
                string categoryUrl = categoryNode.Attributes["href"].Value;//"http://www.amazon.com/Best-Sellers-Appliances/zgbs/appliances/ref=zg_bs_nav_0"

                string categoryStr = categoryNode.InnerText;
                categoryStr = HttpUtility.HtmlDecode(categoryStr);//"Appliances"

                string categoryKey = "";
                if (extractCatKeyFromBestSellerCatUrl(categoryUrl, out categoryKey))
                {
                    //store info
                    categoryItem bestSellerCategoryItem = new categoryItem();
                    bestSellerCategoryItem.Name = categoryStr; //"Appliances"
                    bestSellerCategoryItem.Key = categoryKey; //"appliances"
                    bestSellerCategoryItem.Url = categoryUrl; //"http://www.amazon.com/Best-Sellers-Appliances/zgbs/appliances/ref=zg_bs_nav_0"

                    bestSellerCategoryList.Add(bestSellerCategoryItem);
                }
                else
                {
                    //something wrong
                }
            }
        }
        else
        {
            //something wrong
        }

        return bestSellerCategoryList;
    }
    
    /*
     * [Function]
     * from category key, generate the main category url
     * [Input]
     * instant-video
     * [Output]
     * http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dinstant-video
     * [Note]
     */
    public string generateMainCategoryUrlFromCategoryKey(string categoryKey)
    {
        string mainCategoryUrl = "";

        //http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Dinstant-video&field-keywords=
        //http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Dinstant-video
        mainCategoryUrl = "http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3d" + HttpUtility.UrlEncode(categoryKey);
        //"http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dinstant-video"

        return mainCategoryUrl;
    }

    /*
     * [Function]
     * from amazon main category url extract sub category list
     * [Input]
     * http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dappliances
     * [Output]
     * sub/child categoryItem list
     * [Note]
     */
    public List<categoryItem> extractSubCategoryList(string amazonMainCategoryUrl)
    {
        List<categoryItem> subCategoryList = new List<categoryItem>();

        string respHtml = "";
        respHtml = crl.getUrlRespHtml_multiTry(amazonMainCategoryUrl);

        //http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3dappliances
        //<div id="left">
        //   <div id="leftNav">
        //       <div id="leftNavContainer">
        //            <div id="refinements" data-baserh="n%3A2619525011" data-browseladder="n%3A2619525011">
        //                <h2 >Department</h2>
        //                <ul id="ref_2619526011" data-typeid="n" >
        //                    <li style="margin-left: 0px">
        //                        <strong>Appliances</strong>
        //                    </li>
        //                    <!-- A non-null numberVisibleValues indicates that we should put the non-visible items behind a "See more..." expando, but only if there are enough values available to be hidden. -->
        //                    <li style="margin-left: -2px">
        //                        <a href="/s/ref=lp_2619525011_nr_n_0?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A3737671&amp;bbn=2619526011&amp;ie=UTF8&amp;qid=1371180383&amp;rnid=2619526011">
        //                            <span class="refinementLink">Air Conditioners</span><span class="narrowValue">&nbsp;(8,704)</span>
        //                        </a>
        //                    </li>
        //            ............
        //                    <li style="margin-left: -2px">
        //                        <a href="/s/ref=lp_2619525011_nr_n_28?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A2383576011&amp;bbn=2619526011&amp;ie=UTF8&amp;qid=1371180383&amp;rnid=2619526011">
        //                             <span class="refinementLink">Washers &amp; Dryers</span><span class="narrowValue">&nbsp;(1,390)</span>
        //                        </a>
        //                    </li>
        //                    <li style="margin-left: -2px">
        //                        <a href="/s/ref=lp_2619525011_nr_n_29?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A3741521&amp;bbn=2619526011&amp;ie=UTF8&amp;qid=1371180383&amp;rnid=2619526011">
        //                            <span class="refinementLink">Wine Cellars</span><span class="narrowValue">&nbsp;(3,761)</span>
        //                        </a>
        //                    </li>
        //                </ul>

        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        HtmlNode refinementsNode = htmlDoc.DocumentNode.SelectSingleNode("//div[@id='refinements' and @data-baserh and @data-browseladder]");

        HtmlNodeCollection subCategoryNodeList = refinementsNode.SelectNodes("//ul[@id and @data-typeid]/li/a");
        if ((subCategoryNodeList != null) && (subCategoryNodeList.Count > 0))
        {
            foreach (HtmlNode subCatNode in subCategoryNodeList)
            {
                string subCatUrl = subCatNode.Attributes["href"].Value; //"/s/ref=lp_2619525011_nr_n_0?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A3737671&amp;bbn=2619526011&amp;ie=UTF8&amp;qid=1371183419&amp;rnid=2619526011"
                subCatUrl = constAmazonDomainUrl + subCatUrl; //"http://www.amazon.com/s/ref=lp_2619525011_nr_n_0?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A3737671&amp;bbn=2619526011&amp;ie=UTF8&amp;qid=1371183419&amp;rnid=2619526011"
                subCatUrl = HttpUtility.HtmlDecode(subCatUrl); //"http://www.amazon.com/s/ref=lp_2619525011_nr_n_0?rh=n%3A2619525011%2Cn%3A%212619526011%2Cn%3A3737671&bbn=2619526011&ie=UTF8&qid=1371183419&rnid=2619526011"

                HtmlNode refinementLinkNode = subCatNode.SelectSingleNode("./span[@class='refinementLink']");
                if (refinementLinkNode != null)
                {
                    string subCatName = refinementLinkNode.InnerText; //"Air Conditioners"
                    subCatName = subCatName.Trim();
                    subCatName = HttpUtility.HtmlDecode(subCatName); //"Air Conditioners"

                    //store info
                    categoryItem singleSubCatItem = new categoryItem();
                    singleSubCatItem.Name = subCatName;
                    singleSubCatItem.Key = ""; // sub category no key
                    singleSubCatItem.Url = subCatUrl;

                    subCategoryList.Add(singleSubCatItem);
                }
                else
                {
                    //something wrong
                }
            }
        }
        else
        {
            //something wrong
            gLogger.Debug("can not find subCategoryNodeList");
        }

        return subCategoryList;
    }


    /*
     * [Function]
     * from amazon main url extract main category
     * [Input]
     * http://www.amazon.com/ref=nb_sb_noss_null
     * [Output]
     * categoryItem list, contains 36 main category:
     * Key	"instant-video"	string
     * Name	"Amazon Instant Video"	string
     * ...
     * Key	"watches"	string
     * Name	"Watches"	string
     * [Note]
     */
    public List<categoryItem> extractMainCategoryList(string amazonMainUrl)
    {
        List < categoryItem> mainCategoryList = new List<categoryItem>();

        string respHtml = "";
        //respHtml = crl.getUrlRespHtml(regularCategoryMainUrl);
        respHtml = crl.getUrlRespHtml_multiTry(amazonMainUrl);
        
        /*
        <span id='nav-search-in' class='nav-sprite'>
          <span id='nav-search-in-content' data-value="search-alias=aps">
            All
          </span>
          <span class='nav-down-arrow nav-sprite'></span>
          <select name="url" id="searchDropdownBox" class="searchSelect" title="Search in"   ><option value="search-alias=aps" selected="selected">All Departments</option><option value="search-alias=instant-video">Amazon Instant Video</option><option value="search-alias=appliances">Appliances</option><option value="search-alias=mobile-apps">Apps for Android</option><option value="search-alias=arts-crafts">Arts, Crafts & Sewing</option><option value="search-alias=automotive">Automotive</option><option value="search-alias=baby-products">Baby</option><option value="search-alias=beauty">Beauty</option><option value="search-alias=stripbooks">Books</option><option value="search-alias=mobile">Cell Phones & Accessories</option><option value="search-alias=apparel">Clothing & Accessories</option><option value="search-alias=collectibles">Collectibles</option><option value="search-alias=computers">Computers</option><option value="search-alias=financial">Credit Cards</option><option value="search-alias=electronics">Electronics</option><option value="search-alias=gift-cards">Gift Cards Store</option><option value="search-alias=grocery">Grocery & Gourmet Food</option><option value="search-alias=hpc">Health & Personal Care</option><option value="search-alias=garden">Home & Kitchen</option><option value="search-alias=industrial">Industrial & Scientific</option><option value="search-alias=jewelry">Jewelry</option><option value="search-alias=digital-text">Kindle Store</option><option value="search-alias=magazines">Magazine Subscriptions</option><option value="search-alias=movies-tv">Movies & TV</option><option value="search-alias=digital-music">MP3 Music</option><option value="search-alias=popular">Music</option><option value="search-alias=mi">Musical Instruments</option><option value="search-alias=office-products">Office Products</option><option value="search-alias=lawngarden">Patio, Lawn & Garden</option><option value="search-alias=pets">Pet Supplies</option><option value="search-alias=shoes">Shoes</option><option value="search-alias=software">Software</option><option value="search-alias=sporting">Sports & Outdoors</option><option value="search-alias=tools">Tools & Home Improvement</option><option value="search-alias=toys-and-games">Toys & Games</option><option value="search-alias=videogames">Video Games</option><option value="search-alias=watches">Watches</option></select>
        </span>
         */
        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        HtmlNode categorySelectNode = htmlDoc.DocumentNode.SelectSingleNode("//span[@id='nav-search-in' and @class='nav-sprite']/select[@name='url' and @id='searchDropdownBox' and @class='searchSelect']");
        if (categorySelectNode != null)
        {
            HtmlNodeCollection optionNodeList = categorySelectNode.SelectNodes(".//option[@value]");

            //omit first one:
            //<option value="search-alias=aps" selected="selected">All Departments</option>
            optionNodeList.Remove(0);

            foreach (HtmlNode singleOptionNode in optionNodeList)
            {
                //<option value="search-alias=instant-video">Amazon Instant Video</option>
                //<option value="search-alias=appliances">Appliances</option>
                //...
                //<option value="search-alias=watches">Watches</option>
                string searchValue = singleOptionNode.Attributes["value"].Value; //search-alias=instant-video
                string categoryKey = ""; //instant-video
                if (crl.extractSingleStr(@"=([a-z\-]+)", searchValue, out categoryKey))
                {
                    //instant-video
                    //appliances
                    //mobile-apps

                    string generalCategory = singleOptionNode.InnerText; //Amazon Instant Video
                    //string generalCategory = singleOptionNode.NextSibling.InnerText; //Amazon Instant Video

                    //store info
                    categoryItem singleCategoryItem = new categoryItem();
                    singleCategoryItem.Name = generalCategory;
                    singleCategoryItem.Key = categoryKey;
                    singleCategoryItem.Url = generateMainCategoryUrlFromCategoryKey(categoryKey);

                    //add to list
                    mainCategoryList.Add(singleCategoryItem);
                }
                else
                {
                    //something wrong
                    gLogger.Debug(String.Format("can not extart main category key for html node {0} for {1}",singleOptionNode.ToString(),amazonMainUrl));
                }
            }
        }
        else
        {
            //something wrong
            gLogger.Debug("can not find categorySelectNode for " + amazonMainUrl);
        }

        return mainCategoryList;
    }

    /*
     * [Function]
     * from html extract product title
     * [Input]
     * http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1369487181&sr=1-1
     * [Output]
     * Kindle Fire HD Tablet
     * [Note]
     */
    public string extractProductTitle(string respHtml)
    {
        string productTitle = "";
        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1369487181&sr=1-1
        //<span id="btAsinTitle">Kindle Fire HD Tablet</span>

        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_2?ie=UTF8&qid=1369487181&sr=1-2
        //<span id="btAsinTitle">Kindle Paperwhite</span>

        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_3?ie=UTF8&qid=1369487181&sr=1-3
        //<span id="btAsinTitle">Garmin nüvi 50LM 5-Inch Portable GPS Navigator with Lifetime Maps (US)</span>

        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_4?ie=UTF8&qid=1369487181&sr=1-4
        //<span id="btAsinTitle">GE MWF Refrigerator Water Filter, 1-Pack</span>
        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        HtmlNode titleNode = htmlDoc.DocumentNode.SelectSingleNode("//span[@id='btAsinTitle']");
        if (titleNode != null)
        {
            productTitle = titleNode.InnerText; //Kindle Paperwhite
        }
        else
        {
            //something wrong 
        }
        return productTitle;
    }

    /*
     * [Function]
     * from html extract product bullets
     * [Input]
     * html of http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_3?ie=UTF8&qid=1369726182&sr=1-3
     * [Output]
     * string list:
     *  Replacement water filter for refrigerators
     *  Works with a wide-range of GE models
     *  Replaces GWF, GWFA, GWF01, GWF06, MWFA
     *  Eliminates home delivery/store bought bottled water
     *  Should be replaced every 6 months
     * [Note]
     * 1. normally, only have 5 bullets
     */
    public bool extractProductBulletList(string respHtml, out List<string> bulletList)
    {
        bool gotBullets = false;

        bulletList = new List<string>();
        
        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;

        //-----------------bullets-----------------
        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_1?ie=UTF8&qid=1369487181&sr=1-1
        //<div id="kindle-feature-bullets-atf">
        //  <div>
        //    <ul>
        //        <li><span>1280x800 HD display with polarizing filter and anti-glare technology for rich color and deep contrast from any viewing angle</span></li><li><span>Exclusive Dolby audio and dual-driver stereo speakers for immersive, virtual surround sound</span></li><li><span>World's first tablet with dual-band, dual-antenna Wi-Fi for over 35% faster downloads and streaming (<a href="#" id="kpp-popover-0" >compared to the iPad mini</a><script type="text/javascript">
        //amznJQ.available('jQuery', function() { 
        //(function ($) {
        //amznJQ.available('popover', function() {
        //    var content = '<h2 style="font-size: 17px;">Two Antennas, Better Bandwidth</h2>' 

        //    + '<img src="http://g-ec2.images-amazon.com/images/G/01/kindle/dp/2012/KT/tate_feature-wifi._V395653267_.gif"/>'

        //    $('#kpp-popover-0').amazonPopoverTrigger({
        //        literalContent: content,
        //        closeText: 'Close',
        //        title: '&nbsp;',
        //        width: 550,
        //        location: 'centered'
        //    });

        //});
        //}(jQuery)); 
        //}); 

        //</script>)</span></li><li><span>High performance 1.2 Ghz dual-core processor with Imagination PowerVR 3D graphics core for fast and fluid performance</span></li><li><span>Over 23 million movies, TV shows, songs, magazines, books, audiobooks, and popular apps and games such as <i>Facebook</i>, <i>Netflix</i>, <i>Twitter</i>, <i>HBO GO</i>, <i>Pandora</i>, and <i>Angry Birds Space</i></span></li><li><span>Integrated support for Facebook, Twitter, Gmail, Hotmail, Yahoo! and more, as well as Exchange calendar, contacts, and email</span></li><li><span>Front-facing HD camera for taking photos or making video calls using Skype, Facebook, and other apps</span></li><li><span>Free unlimited cloud storage for all your Amazon content</span></li><li><span>Kindle FreeTime &mdash; a free, personalized tablet experience just for kids on the Kindle Fire HD. Set daily screen limits, and give access to appropriate content for each child</span></li><li><span>Kindle FreeTime Unlimited &mdash; just for kids. Unlimited access to books, games, apps, movies and TV shows. <a href="http://www.amazon.com/gp/feature.html?&docId=1000863021" target="_blank">Learn more</a></span></li><li><span><img src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/prime.gif"/> Prime Instant Video &mdash; unlimited, instant streaming of thousands of popular movies and TV shows</span></li><li><span><img src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/prime.gif"/> Kindle Owners' Lending Library &mdash; Kindle owners can choose from more than 270,000 books to borrow for free with no due dates, including over 100 current and former <i>New York Times</i> best sellers</span></li><li><span><b>NEW:</b> Kindle Fire owners get 500 <b>Amazon Coins</b> (a $5 value) to spend on Kindle Fire apps and games. <a href="http://www.amazon.com/gp/feature.html/ref=zeroes_surl_c_landing?docId=1001166401" target="_blank">Learn more</a></span></li>
        //    </ul>
        //  </div>
        //</div>

        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_2?ie=UTF8&qid=1369487181&sr=1-2
        //<div id="kindle-feature-bullets-atf">
        //  <div>
        //    <ul>
        //        <li><span>Patented built-in light evenly illuminates the screen to provide the perfect reading experience in all lighting conditions</span></li><li><span>Paperwhite has 62% more pixels for brilliant resolution</span></li><li><span>25% better contrast for sharp, dark text</span></li><li><span>Even in bright sunlight, Paperwhite delivers clear, crisp text and images with no glare</span></li><li><span>New hand-tuned fonts - 6 font styles, 8 adjustable sizes</span></li><li><span>8-week battery life, even with the light on</span></li><li><span>Holds up to 1,100 books - take your library wherever you go</span></li><li><span>Built-in Wi-Fi lets you download books in under 60 seconds</span></li><li><span>New Time to Read feature uses your reading speed to let you know when you'll finish your chapter</span></li><li><span>Massive book selection. Lowest prices. Over a million titles less than $9.99</span></li><li><span>180,000 Kindle-exclusive titles that you won't find anywhere else, including books by best-selling authors such as Kurt Vonnegut</span></li><li><span>Supports children's books and includes new parental controls</span></li><li><span><img src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KS/prime.gif" /> Kindle Owners' Lending Library - with Amazon Prime, Kindle owners can choose from more than 270,000 books to borrow for free with no due dates, including over 100 current and former <i>New York Times</i> best sellers</span></li>
        //    </ul>
        //  </div>
        //</div>


        //http://www.amazon.com/GE-MWF-Refrigerator-Filter-1-Pack/dp/B000AST3AK/ref=lp_1055398_1_3?ie=UTF8&qid=1369726182&sr=1-3
        //<div id="feature-bullets-atf">
        //<table cellpadding="0" cellspacing="0" border="0">
        //  <tr>
        //    <td class="bucket normal" style="padding:0px">
        //      <div class="content" style="margin-left:15px;">
        //        <ul style="list-style-type: disc;">
        //      <li><span>Replacement water filter for refrigerators</span></li>
        //      <li><span>Works with a wide-range of GE models</span></li>
        //      <li><span>Replaces GWF, GWFA, GWF01, GWF06, MWFA</span></li>
        //      <li><span>Eliminates home delivery/store bought bottled water</span></li>
        //      <li><span>Should be replaced every 6 months</span></li>
        //        </ul>
        //      </div>
        //    <span class="caretnext">&#155;</span>
        //       <a href="#productDetails" style="font-size:12px">
        //    See more product details </a>
        //    </td>
        //  </tr>
        //</table>
        //</div>

        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_6?ie=UTF8&qid=1369727413&sr=1-6
        //<div id="feature-bullets_feature_div">
        //<hr noshade="noshade" size="1" class="bucketDivider" />
        //<table cellpadding="0" cellspacing="0" border="0">
        //  <tr>
        //    <td class="bucket normal">
        //      <h2>Product Features</h2>
        //    <div class="disclaim">Edition: <strong>5-Inch with Lifetime Maps</strong></div>
        //          <div class="content">
        //        <ul style="list-style-type: disc; margin-left: 25px;">
        //       <li>5-inch LCD display,Memory Card Supported: microSD Card</li>
        //       <li>Free lifetime maps with over 6 million points of interest; Hear spoken street names</li>
        //       <li>Speed limit indicator</li>
        //       <li>USB mass storage device is compatible with Windows XP or newer and Mac OS X 10.4 or later</li>
        //       <li>Trip computer records mileage, max speed, total time and more,Lane assist with junction view</li>
        //        </ul>
        //        <div>
        //            <span class="caretnext">&#155;</span>
        //                    <a href="#productDetails">
        //    See more product details </a>
        //                </div>
        //      </div>
        //    </td>
        //  </tr>
        //</table>
        //</div>

        //http://www.amazon.com/SODIAL-Colorful-Magnetic-Numbers-Educational/dp/B008RRPLN4/ref=sr_1_58?s=home-garden&ie=UTF8&qid=1369730932&sr=1-58
        //<table cellpadding="0" cellspacing="0" border="0">
        //  <tr>
        //    <td class="bucket normal">
        //      <h2>Product Features</h2>
        //      <div class="content">
        //        <ul style="list-style-type: disc; margin-left: 25px;">
        //       <li>Numbers Wooden Fridge Magnets</li>
        //       <li>Funky Fridge Magnets</li>
        //       <li>Fridge Colorful Magnetic</li>
        //       <li>Numbers Magnetic</li>
        //       <li>Fridge Magnets</li>
        //        </ul>
        //      </div>
        //    </td>
        //  </tr>
        //</table>

        //http://www.amazon.com/Tech-Armor-Definition-Protectors-Replacement/dp/B00BT7RAPG/ref=sr_1_4?s=wireless&ie=UTF8&qid=1369754056&sr=1-4
        //<div class="bucket">
        //  <a name="technical_details" id="technical_details"></a><h2>Technical Details</h2>   
        //  <div class="content">
        //<ul style="list-style: disc; margin-left: 25px;">
        //<li>High Definition Transparency Film that ensures maximum resolution for your Galaxy S4</li>
        //<li>TruTouch Sensitivity for a natural feel that provides flawless touch screen accuracy</li>
        //<li>Protects your Samsung AMOLED Display from unwanted scratches</li>
        //<li>Repels dust and will reduce signs of daily wear</li>
        //<li>Made from the highest quality Japanese PET Film with 100% Bubble-Free Adhesives for easy installation and no residue when removed</li></ul>
        //<span class="caretnext">&#155;</span>&nbsp;
        //<a href="http://www.amazon.com/Tech-Armor-Definition-Protectors-Replacement/dp/tech-data/B00BT7RAPG/ref=de_a_smtd">See more technical details</a>
        // </div>
        //</div>


        //------ for bullets ------
        HtmlNode bulletsNode = null;
        HtmlNodeCollection bulletsNodeList = null;
        string bulletXpath = "";

        if (bulletsNode == null)
        {
            //<div id="feature-bullets_feature_div">
            //<div id="kindle-feature-bullets-atf">
            HtmlNode featureBulletsAtfNode = rootNode.SelectSingleNode("//div[contains(@id,'feature-bullets-atf')]");
            if (featureBulletsAtfNode != null)
            {
                bulletsNode = featureBulletsAtfNode;
                //<li><span>1280x800 HD display with polarizing filter and anti-glare technology for rich color and deep contrast from any viewing angle</span></li>
                bulletXpath = ".//li/span";
            }
        }

        if (bulletsNode == null)
        {
            //<div id="feature-bullets_feature_div">
            HtmlNode featureBulletsDivNode = rootNode.SelectSingleNode("//div[@id='feature-bullets_feature_div']");
            if (featureBulletsDivNode != null)
            {
                bulletsNode = featureBulletsDivNode;
                //<li>5-inch LCD display,Memory Card Supported: microSD Card</li>
                bulletXpath = ".//li";
            }
        }

        if (bulletsNode == null)
        {
            //<td class="bucket normal">
            HtmlNode tdBucketNormalNode = rootNode.SelectSingleNode("//td[@class='bucket normal']");
            if (tdBucketNormalNode != null)
            {
                bulletsNode = tdBucketNormalNode;
                //<li>Numbers Wooden Fridge Magnets</li>
                bulletXpath = ".//li";
            }
        }

        if (bulletsNode == null)
        {
            //<div class="bucket">
            HtmlNode bucketDivNode = rootNode.SelectSingleNode("//div[@class='bucket']");
            if (bucketDivNode != null)
            {
                bulletsNode = bucketDivNode;
                //<li>High Definition Transparency Film that ensures maximum resolution for your Galaxy S4</li>
                bulletXpath = ".//li";
            }
        }
        
        //finnal process
        if (bulletsNode != null)
        {
            bulletsNodeList = bulletsNode.SelectNodes(bulletXpath);

            //special:
            //maybe has more than 5 bullets
            //http://www.amazon.com/AmazonBasics-Lightning-Compatible-Cable-inch/dp/B00B5RGAWY/ref=sr_1_3?s=wireless&ie=UTF8&qid=1369753764&sr=1-3
            //has feature-bullets_feature_div, but no content -> bulletsNodeList is null
            if (bulletsNodeList != null)
            {
                gotBullets = true;

                for (int idx = 0; idx < bulletsNodeList.Count; idx++)
                {
                    HtmlNode curBulletNode = bulletsNodeList[idx];

                    HtmlNode noJsNode = crl.removeSubHtmlNode(curBulletNode, "script");
                    HtmlNode noStyleNode = crl.removeSubHtmlNode(curBulletNode, "style");

                    string bulletStr = noStyleNode.InnerText;
                    bulletList.Add(bulletStr);
                }
            }
            else
            {
                //something wrong
            }
        }
        else 
        {
            //some indeed no bullets
            //but maybe some has, but fail to find -> wrong
        }

        return gotBullets;
    }

    /*
     * [Function]
     * from html extract product description
     * [Input]
     * html of http://www.amazon.com/Legend-Zelda-Hyrule-Historia/dp/1616550414/ref=lp_1_1_1?ie=UTF8&qid=1367990173&sr=1-1
     * [Output]
     * Dark Horse Books and Nintendo team up to bring you The Legend of Zelda: Hyrule Historia, containing an unparalleled collection of historical information on The Legend of Zelda franchise. This handsome hardcover contains never-before-seen concept art, the full history of Hyrule, the official chronology of the games, and much more! Starting with an insightful introduction by the legendary producer and video-game designer of Donkey Kong, Mario, and The Legend of Zelda, Shigeru Miyamoto, this book is crammed full of information about the storied history of Link's adventures from the creators themselves! As a bonus, The Legend of Zelda: Hyrule Historia includes an exclusive comic by the foremost creator of The Legend of Zelda manga - Akira Himekawa!
     * [Note]
     * 1. normally, only have description, some special not have
     */
    public bool extractProductDescription(string respHtml, out string description)
    {
        bool isFoundDescription = false;
        description = "";

        HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        HtmlNode rootNode = htmlDoc.DocumentNode;
        
        //-----------------description-----------------
        //http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_3?ie=UTF8&qid=1369487181&sr=1-3
        //<div class="bucket" id="productDescription">
        // <h2>Product Description</h2>
        //    <div class="disclaim">Edition: <strong>5-Inch with Lifetime Maps</strong></div>
        //     <div class="content">
        //           <h3 class="productDescriptionSource" ></h3>
        //       <div class="productDescriptionWrapper" >
        //       With a big 5&rdquo; (12.7 cm) touchscreen, more than 5 million points of  <img src="http://g-ecx.images-amazon.com/images/G/01/B005HSDL8S/cf-lg-5.jpg" style="float: right;" />interest (POIs) and spoken turn-by-turn directions, n&uuml;vi 50LM makes  driving fun again. Plus, with FREE lifetime map updates, you always can  keep your roads and POIs up to date.<br /><br /> <h3>Get Turn-by-Turn Directions</h3> <p>n&uuml;vi 50LM's intuitive interface greets you with 2 simple choices:  "Where To?" and "View Map." Touch the screen to easily look up addresses  and services and to be guided to your destination with voice-prompted,  turn-by-turn directions that speak street names. It comes in 2 mapping  versions and has preloaded maps for the lower 48 states plus Hawaii and  Puerto Rico. n&uuml;vi 50LM&rsquo;s speed limit indicator shows you how fast you can go  on most major roads. With its "Where Am I?" emergency locator, you  always know your location. It also comes preloaded with millions of POIs  and offers the ability to add your own.</p> <h3>Enjoy FREE Lifetime Map Updates</h3> <p><img src="http://g-ecx.images-amazon.com/images/G/01/B005HSDL8S/lf-lg-4.jpg" style="float: left;" />With FREE lifetime map&sup1; updates, you always have the most up-to-date  maps, POIs and navigation information available at your fingertips. Map  updates are available for download up to 4 times a year with no  subscription or update fees and no expiration dates.</p> <h3>Know the Lane Before It&rsquo;s Too Late</h3> <p>Now there&rsquo;s no more guessing which lane you need to be in to make an  upcoming turn. Available in select metropolitan areas, lane assist with  junction view guides you to the correct lane for an approaching turn or  exit, making unfamiliar intersections and exits easy to navigate. It  realistically displays road signs and junctions on your route along with  arrows that indicate the proper lane for navigation. <img src="http://g-ecx.images-amazon.com/images/G/01/B005HSDL8S/pd-01-lg-4.jpg" style="float: right;" /></p> <p><em>&sup1; FREE lifetime map updates entitle you to receive up to 4 map  data updates per year, when and as such updates are made available on  the Garmin website, for this specific Garmin product only until this  product&rsquo;s useful life expires or Garmin no longer receives map data from  its third party supplier, whichever is shorter. The updates you receive  will be updates to the same geographic map data originally included  with your Garmin product when originally purchased. Garmin may terminate  your lifetime map updates at any time if you violate any of the terms  of the End User License Agreement accompanying your n&uuml;vi product. <br /></em></p> <p><em></em></p> <h3>What's in the Box:</h3> <ul> <li>n&uuml;vi 50LM</li> <li>City Navigator&reg; NT  data with preloaded street maps of the lower 48 states, Hawaii, Puerto  Rico, U.S. Virgin Islands, Cayman Islands, Bahamas, French Guiana,  Guadeloupe, Martinique, Saint Barth&eacute;lemy and Jamaica </li> <li>Lifetime maps&sup1; (indicated by "LM" after model number on the box)</li> <li>Vehicle suction cup mount&sup2;</li> <li>Vehicle power cable</li> <li>USB cable</li> <li>Quick start manual</li> </ul>
        //      <div class="emptyClear"> </div>
        //      </div>
        //  </div>
        //</div>

        //http://www.amazon.com/Legend-Zelda-Hyrule-Historia/dp/1616550414/ref=lp_1_1_1?ie=UTF8&qid=1367990173&sr=1-1
        //<div id="ps-content" class="bucket">
        //  <h2>Book Description</h2>
        //<div class="buying"><span class="byLinePipe">Release date: </span><span style="font-weight: bold;">January 29, 2013</span> </div>
        //  <div class="content">
        //    <div id="outer_postBodyPS" style="overflow:hidden; z-index: 1; ">
        //      <div id="postBodyPS" style="overflow: hidden;">
        //         <div>Dark Horse Books and Nintendo team up to bring you The Legend of Zelda: Hyrule Historia, containing an unparalleled collection of historical information on The Legend of Zelda franchise. This handsome hardcover contains never-before-seen concept art, the full history of Hyrule, the official chronology of the games, and much more! Starting with an insightful introduction by the legendary producer and video-game designer of Donkey Kong, Mario, and The Legend of Zelda, Shigeru Miyamoto, this book is crammed full of information about the storied history of Link's adventures from the creators themselves! As a bonus, The Legend of Zelda: Hyrule Historia includes an exclusive comic by the foremost creator of The Legend of Zelda manga - Akira Himekawa!</div>
        //      </div>
        //    </div>
        //    <div id="psGradient" class="psGradient" style="display:none;"></div>
        //    <div id="psPlaceHolder" style="display:none; height: 20px;">
        //      <div id="expandPS" style="display:none; z-index: 3;">
        //        <span class="swSprite s_expandChevron"></span>
        //        <a class="showMore" onclick="amz_expandPostBodyDescription('PS', ['psGradient', 'psPlaceHolder']); return false;" href="#">Show more</a>
        //      </div>
        //    </div>
        //    <div id="collapsePS" style="display:none; padding-top: 3px;">
        //      <span class="swSprite s_collapseChevron"></span>
        //      <a class="showLess" onclick="amz_collapsePostBodyDescription('PS', ['psGradient', 'psPlaceHolder']); return false;" href="#">Show less</a>
        //    </div>
        //<noscript>
        //  <style type='text/css'>
        //    #outer_postBodyPS {
        //      display: none;
        //    }
        //    #psGradient {
        //      display: none;
        //    }
        //    #psPlaceHolder {
        //      display: none;
        //    }
        //    #psExpand {
        //      display: none;
        //    }
        //  </style>
        //    <div id="postBodyPS">Dark Horse Books and Nintendo team up to bring you The Legend of Zelda: Hyrule Historia, containing an unparalleled collection of historical information on The Legend of Zelda franchise. This handsome hardcover contains never-before-seen concept art, the full history of Hyrule, the official chronology of the games, and much more! Starting with an insightful introduction by the legendary producer and video-game designer of Donkey Kong, Mario, and The Legend of Zelda, Shigeru Miyamoto, this book is crammed full of information about the storied history of Link's adventures from the creators themselves! As a bonus, The Legend of Zelda: Hyrule Historia includes an exclusive comic by the foremost creator of The Legend of Zelda manga - Akira Himekawa!</div>
        //</noscript>
        //  </div>
        //</div>


        //------ for description ------
        HtmlNode descriptionNode = null;
        HtmlNode filteredDescriptionNode = null;
        if (descriptionNode == null)
        {
            //<div id="ps-content" class="bucket">
            // <div class="content">
            //  <div id="outer_postBodyPS" style="overflow:hidden; z-index: 1; ">
            //   <div id="postBodyPS" style="overflow: hidden;">
            //    <div>
            HtmlNode postBodyNode = rootNode.SelectSingleNode(
                "//div[@class='bucket']/div[@class='content']/div[@id='outer_postBodyPS']/div[@id='postBodyPS']/div");
            if (postBodyNode != null)
            {
                descriptionNode = postBodyNode;
            }
        }

        if (descriptionNode == null)
        {
            //<div class="bucket" id="productDescription">
            // <div class="content">
            //  <div class="productDescriptionWrapper" >
            HtmlNode postBodyNode = rootNode.SelectSingleNode(
                "//div[@class='bucket']/div[@class='content']/div[@class='productDescriptionWrapper']");
            if (postBodyNode != null)
            {
                descriptionNode = postBodyNode;
            }
        }
        
        //finnal process
        if (descriptionNode == null)
        {
            isFoundDescription = false;
        }
        else
        {
            HtmlNode noPNode = crl.removeSubHtmlNode(descriptionNode, "p");
            HtmlNode noScriptNode = crl.removeSubHtmlNode(noPNode, "script");
            HtmlNode noStyleNode = crl.removeSubHtmlNode(noScriptNode, "style");
            HtmlNode noTableNode = crl.removeSubHtmlNode(noStyleNode, "table");

            filteredDescriptionNode = noTableNode;

            //description
            description = filteredDescriptionNode.InnerText;

            isFoundDescription = true;
        }

        return isFoundDescription;
    }


    /*
     * [Function]
     * extract custom large image url list from item custom url
     * [Input]
     * http://www.amazon.com/gp/customer-media/product-gallery/B003C9HUDQ
     * [Output]
     * large image url list
     * 
     * [Note]
     * 1. normally, only have 5 pic, some more:7/10/..., somm less: 1/2/...
     */
    public List<string> extractCustomImageUrlList(string customImageUrl)
    {
        List<string> customImageList = new List<string>();

        string productHtml = crl.getUrlRespHtml_multiTry(customImageUrl);

        //http://www.amazon.com/gp/customer-media/product-gallery/B003C9HUDQ

        //  amznJQ.available("cmuMediaGalleryController", function () {
        //    var state = {
        //   "pageUrl" : "/gp/customer-media/product-gallery/B003C9HUDQ?ie=UTF8&*Version*=1&*entries*=0",
        //   "page" : 0,
        //   "currentImage" : {
        //      "width" : 500,
        //      "authorID" : "A1NSXYQFE2410F",
        //      "isremote" : 0,
        //      "authorName" : "cknudson",
        //      "uploadDate" : "5/30/12",
        //      "mediaObjectID" : null,
        //      "isSlateImage" : 0,
        //      "height" : 375,
        //      "caption" : "Used along with Umbra Dragonflies as a memorial wall for our son.",
        //      "helpfulVotes" : 17,
        //      "annotationsCount" : 0,
        //      "url" : "http://ecx.images-amazon.com/images/I/610FYc8JxIL.jpg",
        //      "id" : "mo3ML9P6YYWJBCI",
        //      "totalVotes" : 17
        //   },
        //   "anchorTypeID" : "ASIN",
        //   "imageList" : [
        //      {
        //         "width" : 500,
        //         "isremote" : 0,
        //         "annotationsCount" : 0,
        //         "isSlateImage" : 0,
        //         "url" : "http://ecx.images-amazon.com/images/I/610FYc8JxIL.jpg",
        //         "id" : "mo3ML9P6YYWJBCI",
        //         "height" : 375
        //      },
        //      {
        //         "width" : 500,
        //         "isremote" : 0,
        //         "annotationsCount" : 0,
        //         "isSlateImage" : 0,
        //         "url" : "http://ecx.images-amazon.com/images/I/51boViyAS2L.jpg",
        //         "id" : "mo3SK1IKQNFENLP",
        //         "height" : 476
        //      },
        //      {
        //         "width" : 500,
        //         "isremote" : 0,
        //         "annotationsCount" : 0,
        //         "isSlateImage" : 0,
        //         "url" : "http://ecx.images-amazon.com/images/I/51sadTKDhOL.jpg",
        //         "id" : "mo3R31OJGG2XQ6S",
        //         "height" : 282
        //      },
        //      {
        //         "width" : 500,
        //         "isremote" : 0,
        //         "annotationsCount" : 0,
        //         "isSlateImage" : 0,
        //         "url" : "http://ecx.images-amazon.com/images/I/51Z4m%2BvmMdL.jpg",
        //         "id" : "mo1U55IBOPNVGLA",
        //         "height" : 282
        //      }
        //   ],
        //   "anchorID" : "B003C9HUDQ",
        //   "countAllRemoteImages" : 0,
        //   "totalPages" : 1,
        //   "application" : "cmu",
        //   "currentImagePage" : 0,
        //   "pageSize" : 7,
        //   "sort" : "rating",
        //   "currentImageNumber" : 0,
        //   "mediaType" : null,
        //   "totalImages" : 4,
        //   "currentImagePageOffset" : 0
        //};

        string strMediaGalleryStateJson = "";
        if (crl.extractSingleStr(@"amznJQ\.available\(""cmuMediaGalleryController"",\s*function\s*\(\s*\)\s*\{\s*var\s+state\s*=\s*(\{.+?})\s*;\s*var\s+config\s*=", productHtml, out strMediaGalleryStateJson, RegexOptions.Singleline))
        {
            Dictionary<string, Object> stateDict = (Dictionary<string, Object>)crl.jsonToDict(strMediaGalleryStateJson);

            if ((stateDict != null) && (stateDict.ContainsKey("imageList")))
            {
                Object imageListObj = null;
                if (stateDict.TryGetValue("imageList", out imageListObj))
                {
                    //List<Dictionary<string, Object>> imageDictList = (List<Dictionary<string, Object>>)imageListObj;
                    Object[] imageObjArr = (Object[])imageListObj;
                    foreach (Object imageDictObj in imageObjArr)
                    {
                        Dictionary<string, Object> imageDict = (Dictionary<string, Object>)imageDictObj;
                        Object urlObj = null;
                        if (imageDict.TryGetValue("url", out urlObj))
                        {
                            string url = urlObj.ToString();
                            customImageList.Add(url);
                        }
                    }
                }
            }
        }
        else
        {
            //special: no custom image
            //http://www.amazon.com/gp/customer-media/product-gallery/B0009IQXFO

            gLogger.Debug("Not found cmuMediaGalleryController state json for " + customImageUrl);
        }

        return customImageList;
    }

    /*
     * [Function]
     * from html extract image url list
     * [Input]
     * html of http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_2?ie=UTF8&qid=1369820725&sr=1-2
     * [Output]
     * image url list:
     * http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-01-lg._V395919237_.jpg 
     * http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-apps-lg._V396577301_.jpg
     * http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-web-lg._V396577300_.jpg
     * http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-hd-lg._V396577300_.jpg
     * http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-social-lg._V396577301_.jpg
     * 
     * [Note]
     * 1. normally, only have 5 pic
     * 2.special has 7 pic:
     * http://www.amazon.com/Pandamimi-Dexule-Fashion-2-Piece-Protector/dp/B008TO8L1Y/ref=sr_1_79?s=wireless&ie=UTF8&qid=1369754594&sr=1-79
     * http://www.amazon.com/All-Ware-Stainless-Pineapple-De-Corer/dp/B000GA53CO/ref=lp_1055398_1_3?ie=UTF8&qid=1370071787&sr=1-3
     * 3. special:
     * (1)
     * http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_4?ie=UTF8&qid=1370072907&sr=1-4
     * extract from "var colorImages" can got 1 pic
     * but extract from: <div id="main-image-fixed-container">, can got 3 pics
     * (2)
     * http://www.amazon.com/San-Francisco-Bay-Coffee-80-Count/dp/B007Y59HVM/ref=lp_1055398_1_5?ie=UTF8&qid=1370072907&sr=1-5
     * extract from "var colorImages" can got 6 pic
     * but total has 7 pics
     * (3)
     * http://www.amazon.com/Garmin-5-Inch-Portable-Navigator-Lifetime/dp/B0057OCDQS/ref=lp_1055398_1_6?ie=UTF8&qid=1370072907&sr=1-6
     * has 6 pics,
     * but extract from "var colorImages" can got 4 pic
     */
    public string[] extractProductImageList(string productHtml)
    {
        string[] imageUrlList = null;

        //------------------------- Method 1: find div kib-ma-container -------------------------
        //-> got node no contain img tag

        //http://www.amazon.com/Kindle-Paperwhite-Touch-light/dp/B007OZNZG0/ref=lp_1055398_1_1?ie=UTF8&qid=1369818181&sr=1-1
        //from webbrowser:
        //<div id="kib-ma-container-0" class="kib-ma-container" style="z-index: 1;"><div style="position: relative; float: left;"><div style="position: relative;" id="preplayDivmJRPXDWU3S51F"><div style="width: 500px; height: 483px;" class="outercenterslate"><div style="width:500px;height:0" class="centerslate"><span></span><img style="width: 500px; height: 483px;" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-lg._V401028090_.jpg" border="0"></div><div src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-play-btn-off._V389377323_.gif" class="shuttleGradient" style="background: none;height:0px;"><img id="mJRPXDWU3S51FpreplayImageId" style="height:60px;position:absolute;left:0px;top:-60px;" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-play-btn-off._V389377323_.gif" border="0"></div></div></div><div style="overflow: hidden; background: none repeat scroll 0% 0% rgb(0, 0, 0); width: 0px; height: 1px;" id="flashDivmJRPXDWU3S51F"><div id="so_mJRPXDWU3S51F"></div></div></div></div>
        //<div id="kib-ma-container-1" class="kib-ma-container" style="z-index: 0;"><div style="position: relative; float: left;"><div style="position: relative;" id="preplayDivm26TT75OS8GNBU"><div style="width: 500px; height: 483px;" class="outercenterslate"><div style="width:500px;height:0" class="centerslate"><span></span><img style="width: 500px; height: 483px;" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-02-lg._V389678398_.jpg" border="0"></div><div src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-play-btn-off._V389377323_.gif" class="shuttleGradient" style="background: none;height:0px;"><img id="m26TT75OS8GNBUpreplayImageId" style="height:60px;position:absolute;left:0px;top:-60px;" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-play-btn-off._V389377323_.gif" border="0"></div></div></div><div style="overflow: hidden; background: none repeat scroll 0% 0% rgb(0, 0, 0); width: 0px; height: 1px;" id="flashDivm26TT75OS8GNBU"><div id="so_m26TT75OS8GNBU"></div></div></div></div>
        //<div id="kib-ma-container-2" class="kib-ma-container" style="z-index: 0; display: none;">
        //    <img style="width: 500px; height: 483px;" class="kib-ma kib-image-ma" alt="Kindle Paperwhite e-reader" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-lg._V400694812_.jpg" height="483" width="500">
        //</div>
        //<div id="kib-ma-container-3" class="kib-ma-container" style="z-index: 0; display: none;">
        //    <img style="width: 500px; height: 483px;" class="kib-ma kib-image-ma" alt="Kindle Paperwhite e-reader" src="http://g-ecx.images-amazon.com/images/G/01//kindle/dp/2012/KC/KC-slate-04-lg.jpg" height="483" width="500">
        //</div>
        //<div id="kib-ma-container-4" class="kib-ma-container" style="z-index: 0; display: none;">
        //    <img style="width: 500px; height: 483px;" class="kib-ma kib-image-ma" alt="Kindle Paperwhite 3G: thinner than a pencil" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-05-lg._V389396235_.jpg" height="483" width="500">
        //</div>
        //from debug:
        //<div id="kib-ma-container-0" class="kib-ma-container" style="z-index:1;">
        //   <img src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-lg._V401028090_.jpg" width="500" height="483" style="margin-bottom:0px;" />
        //</div>
        //<div id="kib-ma-container-1" class="kib-ma-container" style="z-index:0;">
        //</div>
        //<div id="kib-ma-container-2" class="kib-ma-container" style="margin-bottom:1pxpx; z-index:0; display:none;">
        //    <img class="kib-ma kib-image-ma" alt="Kindle Paperwhite e-reader" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-lg._V400694812_.jpg" width="500" height="483" />
        //</div>
        //<div id="kib-ma-container-3" class="kib-ma-container" style="margin-bottom:1pxpx; z-index:0; display:none;">
        //    <img class="kib-ma kib-image-ma" alt="Kindle Paperwhite e-reader" src="http://g-ecx.images-amazon.com/images/G/01//kindle/dp/2012/KC/KC-slate-04-lg.jpg" width="500" height="483" />
        //</div>
        //<div id="kib-ma-container-4" class="kib-ma-container" style="margin-bottom:1pxpx; z-index:0; display:none;">
        //    <img class="kib-ma kib-image-ma" alt="Kindle Paperwhite 3G: thinner than a pencil" src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-05-lg._V389396235_.jpg" width="500" height="483" />
        //</div>


        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_2?ie=UTF8&qid=1369820725&sr=1-2
        //<div id="kib-ma-container-0" class="kib-ma-container" style="z-index:1;">  
        //   <img src="http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-01-lg._V395919237_.jpg" width="500" height="483" style="margin-bottom:0px;" />
        //</div> 
        //<div id="kib-ma-container-1" class="kib-ma-container" style="z-index:0;">
        //</div>
        //<div id="kib-ma-container-2" class="kib-ma-container" style="z-index:0;">
        //</div>
        //<div id="kib-ma-container-3" class="kib-ma-container" style="z-index:0;">
        //</div>
        //<div id="kib-ma-container-4" class="kib-ma-container" style="z-index:0;">
        //</div>


        //HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(respHtml);
        //HtmlNode rootNode = htmlDoc.DocumentNode;

        //HtmlNodeCollection kibMaNodeList = rootNode.SelectNodes("//div[contains(@id, 'kib-ma-container-') and @class='kib-ma-container']");

        //if (kibMaNodeList != null)
        //{
        //    //for each, found first img -> real large pic
        //    //foreach (HtmlNode kibMaNode in kibMaNodeList)
        //    for (int idx = 0; idx < kibMaNodeList.Count; idx++)
        //    {
        //        HtmlNode kibMaNode = kibMaNodeList[idx];
        //        HtmlNode imgNode = kibMaNode.SelectSingleNode(".//img");
        //        if (imgNode != null)
        //        {
        //            string picUrl = imgNode.Attributes["src"].Value; //"http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-lg._V401028090_.jpg"
        //            imageUrlList[idx] = picUrl;
        //        }
        //        else
        //        {
        //            //something wrong

        //            //special one, no image:
        //            //<div id="kib-ma-container-1" class="kib-ma-container" style="z-index:0;">
        //            //</div>
        //        }
        //    }
        //}
        //else
        //{
        //    //something wrong
        //}


        //------------------------- Method 2: json to dict -------------------------

        //http://www.amazon.com/Kindle-Fire-HD/dp/B0083PWAPW/ref=lp_1055398_1_2?ie=UTF8&qid=1369820725&sr=1-2
        //each preplayImages->L, can got real large pic
        //<script type="text/javascript">
        //window.kibMAs = [
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m1X6Z4SRW3DC3U",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-01-lg._V395919237_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-01-sm._V401027115_.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/kindle/whitney/dp/KW-imv-qt-tn._V167698598_.gif",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-tour-tn._V396577301_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m25IN8SS7SF6O1",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-apps-lg._V396577301_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-apps-sm._V396577300_.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/kindle/whitney/dp/KW-imv-qt-tn._V167698598_.gif",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-apps-tn._V396577301_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m1STLVYO0U0INQ",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-web-lg._V396577300_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-web-sm._V396577306_.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/kindle/whitney/dp/KW-imv-qt-tn._V167698598_.gif",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-web-tn._V396577306_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m3CHUVJSUUOBU4",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-hd-lg._V396577300_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-hd-sm.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/kindle/whitney/dp/KW-imv-qt-tn._V167698598_.gif",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-hd-tn._V396577306_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m3IVTAT62XST8A",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-social-lg._V396577301_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-social-sm.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/kindle/whitney/dp/KW-imv-qt-tn._V167698598_.gif",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-shme-social-tn._V396577301_.jpg"
        //  }
        //}
        //];
        //window.kibConfig = 
        //{


        //[
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "mJRPXDWU3S51F",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-lg._V401028090_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-sm._V401028090_.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-tn._V401028090_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "video", 
        //  "mediaObjectId" : "m26TT75OS8GNBU",
        //  "richMediaObjectId" : "",
        //  "preplayImages" : {
        //      "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-02-lg._V389678398_.jpg", 
        //      "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-02-sm._V402265591_.jpg"
        //  },
        //  "html5PreferPosterHeight" : false,
        //  "thumbnailImageUrls" : {
        //      "default" : "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
        //      "selected" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-02-tn._V389377315_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "image",
        //  "imageUrls" : {
        //    "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-lg._V400694812_.jpg",
        //    "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-sm._V400694812_.jpg",
        //    "rich": {
        //        src: "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
        //        width: null,
        //        height: null
        //    }
        //  },
        //  "altText" : "Kindle Paperwhite e-reader",
        //  "thumbnailImageUrls" : {
        //    "default": "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-tn._V400694812_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "image",
        //  "imageUrls" : {
        //    "L" : "http://g-ecx.images-amazon.com/images/G/01//kindle/dp/2012/KC/KC-slate-04-lg.jpg",
        //    "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-04-sm.jpg",
        //    "rich": {
        //        src: "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
        //        width: null,
        //        height: null
        //    }
        //  },
        //  "altText" : "Kindle Paperwhite e-reader",
        //  "thumbnailImageUrls" : {
        //    "default": "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-04-tn._V389394767_.jpg"
        //  }
        //}
        //,
        //{
        //  "type" : "image",
        //  "imageUrls" : {
        //    "L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-05-lg._V389396235_.jpg",
        //    "S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-05-sm.jpg",
        //    "rich": {
        //        src: "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
        //        width: null,
        //        height: null
        //    }
        //  },
        //  "altText" : "Kindle Paperwhite 3G: thinner than a pencil",
        //  "thumbnailImageUrls" : {
        //    "default": "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-05-tn._V389377336_.jpg"
        //  }
        //}
        //]

        //1. get json string
        string kibMasJson = "";
        string colorImagesJson = "";

        if (crl.extractSingleStr(@"window\.kibMAs\s*=\s*(\[.+?\])\s*;\s*window\.kibConfig\s*=", productHtml, out kibMasJson, RegexOptions.Singleline))
        {
            //2. json to dict
            Object[] dictList = (Object[])crl.jsonToDict(kibMasJson);

            //3. get ["preplayImages"]["L"]
            imageUrlList = new string[dictList.Length];
            crl.emptyStringArray(imageUrlList);

            for (int idx = 0; idx < dictList.Length; idx++)
            {
                Dictionary<string, Object> eachImgDict = (Dictionary<string, Object>)dictList[idx];
                Object imgUrlObj = null;
                if (eachImgDict.ContainsKey("preplayImages"))
                {
                    eachImgDict.TryGetValue("preplayImages", out imgUrlObj);
                }
                else if (eachImgDict.ContainsKey("imageUrls"))
                {
                    eachImgDict.TryGetValue("imageUrls", out imgUrlObj);
                }

                if (imgUrlObj != null)
                {
                    //"L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-lg._V401028090_.jpg", 
                    //"S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-01-sm._V401028090_.jpg"

                    //"L" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-lg._V400694812_.jpg",
                    //"S" : "http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KC/KC-slate-03-sm._V400694812_.jpg",
                    //"rich": {
                    //    src: "http://g-ecx.images-amazon.com/images/G/01/misc/untranslatable-image-id.jpg",
                    //    width: null,
                    //    height: null
                    //}

                    //Type curType = imgUrlObj.GetType();
                    Dictionary<string, Object> imgUrlDict = (Dictionary<string, Object>)imgUrlObj;
                    Object largeImgUrObj = "";
                    if (imgUrlDict.TryGetValue("L", out largeImgUrObj))
                    {
                        //[0]	"http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-01-lg._V395919237_.jpg"
                        //[1]	"http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-02-lg._V389394532_.jpg"
                        //[2]	"http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-03-lg._V389394535_.jpg"
                        //[3]	"http://g-ecx.images-amazon.com/images/G/01//kindle/dp/2012/KT/KT-slate-04-lg.jpg"
                        //[4]	"http://g-ecx.images-amazon.com/images/G/01/kindle/dp/2012/KT/KT-slate-05-lg._V389394532_.jpg"
                        imageUrlList[idx] = largeImgUrObj.ToString();
                    }
                    else
                    {
                        //something wrong
                        //not get all pic
                    }
                }
                else
                {
                    //something wrong
                }
            }
        }
        else if(crl.extractSingleStr(@"var\s+colorImages\s+=\s*{""initial"":(\[{""large"".+?\]}\])}", productHtml, out colorImagesJson))
        {
            //http://www.amazon.com/Pandamimi-Dexule-Fashion-2-Piece-Protector/dp/B008TO8L1Y/ref=sr_1_79?s=wireless&ie=UTF8&qid=1369754594&sr=1-79
            //var colorImages = {"initial":[{"large":"http://ecx.images-amazon.com/images/I/410puGTzNaL.jpg","landing":["http://ecx.images-amazon.com/images/I/410puGTzNaL._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/613THR9iJuL._SL1500_.jpg","thumb":"http://ecx.images-amazon.com/images/I/410puGTzNaL._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/613THR9iJuL._SX300_.jpg","http://ecx.images-amazon.com/images/I/613THR9iJuL._SX300_.jpg"]},{"large":"http://ecx.images-amazon.com/images/I/519xQtKRA%2BL.jpg","landing":["http://ecx.images-amazon.com/images/I/519xQtKRA%2BL._SY300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/71ozNmnjCOL._SL1000_.jpg","thumb":"http://ecx.images-amazon.com/images/I/519xQtKRA%2BL._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/71ozNmnjCOL._SY300_.jpg","http://ecx.images-amazon.com/images/I/71ozNmnjCOL._SY300_.jpg"]},{"large":"http://ecx.images-amazon.com/images/I/41UivS6e73L.jpg","landing":["http://ecx.images-amazon.com/images/I/41UivS6e73L._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/61ZV-PN5VnL._SL1500_.jpg","thumb":"http://ecx.images-amazon.com/images/I/41UivS6e73L._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/61ZV-PN5VnL._SX300_.jpg","http://ecx.images-amazon.com/images/I/61ZV-PN5VnL._SX300_.jpg"]},{"large":"http://ecx.images-amazon.com/images/I/31y%2BwHMFtHL.jpg","landing":["http://ecx.images-amazon.com/images/I/31y%2BwHMFtHL._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/614go2RSKDL._SL1500_.jpg","thumb":"http://ecx.images-amazon.com/images/I/31y%2BwHMFtHL._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/614go2RSKDL._SX300_.jpg","http://ecx.images-amazon.com/images/I/614go2RSKDL._SX300_.jpg"]},{"large":"http://ecx.images-amazon.com/images/I/319AZIP8xTL.jpg","landing":["http://ecx.images-amazon.com/images/I/319AZIP8xTL._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/61pVLmtnppL._SL1500_.jpg","thumb":"http://ecx.images-amazon.com/images/I/319AZIP8xTL._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/61pVLmtnppL._SX300_.jpg","http://ecx.images-amazon.com/images/I/61pVLmtnppL._SX300_.jpg"]}]};

            Object[] dictList = (Object[])crl.jsonToDict(colorImagesJson);
            // {"large":"http://ecx.images-amazon.com/images/I/410puGTzNaL.jpg","landing":["http://ecx.images-amazon.com/images/I/410puGTzNaL._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/613THR9iJuL._SL1500_.jpg","thumb":"http://ecx.images-amazon.com/images/I/410puGTzNaL._SS30_.jpg","main":["http://ecx.images-amazon.com/images/I/613THR9iJuL._SX300_.jpg","http://ecx.images-amazon.com/images/I/613THR9iJuL._SX300_.jpg"]}

            imageUrlList = new string[dictList.Length];
            for (int idx = 0; idx < dictList.Length; idx++)
            {
                Object dict = dictList[idx];
                Dictionary<string, Object> imgInfoDict = (Dictionary<string, Object>)dict;
                Object largeUrlObj = null;
                if (imgInfoDict.TryGetValue("large", out largeUrlObj))
                {
                    string largeImgUrl = largeUrlObj.ToString();
                    imageUrlList[idx] = largeImgUrl;
                }
                else
                {
                    //something wrong
                }
            }
        }


        //special
        //http://www.amazon.com/Paderno-World-Cuisine-A4982799-Tri-Blade/dp/B0007Y9WHQ/ref=lp_1055398_1_3?ie=UTF8&qid=1370594574&sr=1-3
        //total 5 pic:
        //var colorImages = {"initial":[{"large":"http://ecx.images-amazon.com/images/I/41FYj3wTIGL.jpg","landing":["http://ecx.images-amazon.com/images/I/41FYj3wTIGL._SX300_.jpg"],"hiRes":"http://ecx.images-amazon.com/images/I/71e3D5%2BGH6L._SL1451_.jpg","thumb":"http://ecx.images-amazon.com/images/I/41FYj3wTIGL._SS40_.jpg","main":["http://ecx.images-amazon.com/images/I/41FYj3wTIGL._SX355_.jpg","http://ecx.images-amazon.com/images/I/41FYj3wTIGL._SX450_.jpg"]}]};
        //only contain 1 pic, and remain 4 pic in
        //data["customerImages"] = eval('[{"thumb":"http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SS40_.jpg","hasAnnotations":0,"main":["http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SY355_.jpg","http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SY450_.jpg"],"caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/AJYXB96C8CNKF\\">SLC Snowdrops</a>","holderId":"holdermo1SS25OWPE9J72","id":"mo1SS25OWPE9J72","imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_0?ie=UTF8&index=0","isCIU":1},{"thumb":"http://ecx.images-amazon.com/images/I/61alWpZLZrL._SS40_.jpg","hasAnnotations":0,"main":["http://ecx.images-amazon.com/images/I/61alWpZLZrL._SX355_.jpg","http://ecx.images-amazon.com/images/I/61alWpZLZrL._SX450_.jpg"],"caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A341XN0IQ6P3KY\\">PizzaGurl \\"PizzaGurl...</a>","holderId":"holdermo15GHS6TNJUSJE","id":"mo15GHS6TNJUSJE","imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_1?ie=UTF8&index=1","isCIU":1},{"thumb":"http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SS40_.jpg","hasAnnotations":0,"main":["http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SY355_.jpg","http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SY450_.jpg"],"caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A341XN0IQ6P3KY\\">PizzaGurl \\"PizzaGurl...</a>","holderId":"holdermo8778635KTPBK","id":"mo8778635KTPBK","imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_2?ie=UTF8&index=2","isCIU":1},{"thumb":"http://ecx.images-amazon.com/images/I/61JhimJJrjL._SS40_.jpg","hasAnnotations":0,"main":["http://ecx.images-amazon.com/images/I/61JhimJJrjL._SX355_.jpg","http://ecx.images-amazon.com/images/I/61JhimJJrjL._SX450_.jpg"],"caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A1KIIDMM71T6I0\\">Meesh</a>","holderId":"holdermo1P3119KUYN8C2","id":"mo1P3119KUYN8C2","imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_3?ie=UTF8&index=3","isCIU":1}]');

        //special
        //http://www.amazon.com/Glad-Kitchen-Drawstring-Garbage-Gallon/dp/B005GSYXHW/ref=lp_1055398_1_6?ie=UTF8&qid=1370620379&sr=1-6
        //data["customerImages"] = eval('[]');

        string customerImagesJson = "";
        if (crl.extractSingleStr(@"data\[""customerImages""\]\s*=\s*eval\('(.+?)'\);", productHtml, out customerImagesJson))
        {
            //[
            //    {
            //        "thumb" : "http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SS40_.jpg",
            //        "hasAnnotations" : 0,
            //        "main" : [
            //            "http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SY355_.jpg",
            //            "http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SY450_.jpg"
            //        ],
            //        "caption" : "Customer image from <a href=\\" http : //www.amazon.com/gp/customer-media/customer-gallery/AJYXB96C8CNKF\\">SLC Snowdrops</a>",
            //        "holderId":"holdermo1SS25OWPE9J72",
            //        "id":"mo1SS25OWPE9J72",
            //        "imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_0?ie=UTF8&index=0",
            //        "isCIU":1
            //    },
            //    {
            //        "thumb":"http://ecx.images-amazon.com/images/I/61alWpZLZrL._SS40_.jpg",
            //        "hasAnnotations":0,
            //        "main":[
            //            "http://ecx.images-amazon.com/images/I/61alWpZLZrL._SX355_.jpg",
            //            "http://ecx.images-amazon.com/images/I/61alWpZLZrL._SX450_.jpg"
            //        ],
            //        "caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A341XN0IQ6P3KY\\">PizzaGurl \\"PizzaGurl...</a>",
            //        "holderId":"holdermo15GHS6TNJUSJE",
            //        "id":"mo15GHS6TNJUSJE",
            //        "imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_1?ie=UTF8&index=1",
            //        "isCIU":1
            //    },
            //    {
            //        "thumb":"http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SS40_.jpg",
            //        "hasAnnotations":0,
            //        "main":[
            //            "http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SY355_.jpg",
            //            "http://ecx.images-amazon.com/images/I/61F-RaRkNhL._SY450_.jpg"],
            //        "caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A341XN0IQ6P3KY\\">PizzaGurl \\"PizzaGurl...</a>",
            //        "holderId":"holdermo8778635KTPBK",
            //        "id":"mo8778635KTPBK",
            //        "imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_2?ie=UTF8&index=2",
            //        "isCIU":1
            //    },
            //    {
            //        "thumb":"http://ecx.images-amazon.com/images/I/61JhimJJrjL._SS40_.jpg",
            //        "hasAnnotations":0,
            //        "main":[
            //            "http://ecx.images-amazon.com/images/I/61JhimJJrjL._SX355_.jpg",
            //            "http://ecx.images-amazon.com/images/I/61JhimJJrjL._SX450_.jpg"
            //        ],
            //        "caption":"Customer image from <a href=\\"http://www.amazon.com/gp/customer-media/customer-gallery/A1KIIDMM71T6I0\\">Meesh</a>",
            //        "holderId":"holdermo1P3119KUYN8C2",
            //        "id":"mo1P3119KUYN8C2",
            //        "imageLink":"/gp/customer-media/product-gallery/B0007Y9WHQ/ref=cm_ciu_pdp_images_3?ie=UTF8&index=3",
            //        "isCIU":1
            //    }
            //]

            //convert \\ to \
            customerImagesJson = customerImagesJson.Replace("\\\\", "\\");

            Object[] dictList = (Object[])crl.jsonToDict(customerImagesJson);
            
            int newImgListLen = dictList.Length;
            int startImgListIdx;

            //retain previously found img
            if ((imageUrlList != null) && (imageUrlList.Length > 0))
            {
                int oldImgListLen = imageUrlList.Length;
                int totalImgListLen = oldImgListLen + newImgListLen;

                string[] oldImgList = imageUrlList;
                imageUrlList = new string[totalImgListLen];
                oldImgList.CopyTo(imageUrlList, 0);

                startImgListIdx = oldImgListLen;
            }
            else
            {
                imageUrlList = new string[newImgListLen];

                startImgListIdx = 0;
            }

            for (int dictListIdx = 0; dictListIdx < dictList.Length; dictListIdx++)
            {
                Object dict = dictList[dictListIdx];
                Dictionary<string, Object> imgInfoDict = (Dictionary<string, Object>)dict;

                Object mainListObj = null;
                if (imgInfoDict.TryGetValue("main", out mainListObj))
                {
                    Object[] mainUrlList = (Object[])mainListObj;
                    if (mainUrlList.Length >= 2)
                    {
                        //http://www.amazon.com/gp/product/B003BIG0DO/ref=twister_B000AST3AK?ie=UTF8&psc=1
                        //here have 5 item
                        //0:                http://ecx.images-amazon.com/images/I/5135SdQWHxL._SY445_.jpg
                        //1-4: all same:    http://ecx.images-amazon.com/images/I/5135SdQWHxL.jpg

                        //http://www.amazon.com/Maytag-UKF8001-Refrigerator-Filter-1-Pack/dp/B001XW8KW4/ref=lp_1055398_1_7?ie=UTF8&qid=1370620379&sr=1-7
                        //all 5 is: http://ecx.images-amazon.com/images/I/31Up08C%2BZpL.jpg

                        //normal: second one is large img url
                        string largeImgUrl = mainUrlList[1].ToString(); //http://ecx.images-amazon.com/images/I/71WzNwqiuzL._SY450_.jpg
                        imageUrlList[startImgListIdx + dictListIdx] = largeImgUrl;
                    }
                    else
                    {
                        //something wrong
                    }                   
                }
                else
                {
                    //something wrong
                }
            }
        }

        return imageUrlList;
    }
}
