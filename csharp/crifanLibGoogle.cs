/*
 * [File]
 * crifanLibGoogle.cs
 * 
 * [Function]
 * Crifan Lib of C# version for Google
 * 
 * [Note]
 * 1.use crifanLib.cs
 * http://www.crifan.com/crifan_released_all/crifanlib/
 * http://www.crifan.com/crifan_csharp_lib_crifanlib_cs/
 * 2.use HtmlAgilityPack
 *
 * [Version]
 * v1.1
 * 
 * [update]
 * 2013-06-27
 * 
 * [Author]
 * Crifan Li
 * 
 * [Contact]
 * http://www.crifan.com/contact_me/
 * 
 * [History]
 * [v1.1]
 * 1. update extractGoogleSearchResult
 * 
 * [v1.0]
 * 1. initial added 
 * 
 */

using System;
using System.Collections.Generic;
using System.Text;

using HtmlAgilityPack;
using System.Web;
using System.Net;

public class crifanLibGoogle
{
    public crifanLib crl;

    public struct googleSearchResultItem
    {
        public string Title { get; set; }
        public string Url { get; set; }

        //TODO: add Description
    }

    public crifanLibGoogle()
    {
        //!!! for load embedded dll: (1) register resovle handler
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

        //init something
        crl = new crifanLib();
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
     * extract google search result item from google search url or its html
     * [Input]
     * url:
     * http://www.google.com.hk/search?q=weight%20loss+%22Sponsor%20Charity%22
     * or its html
     * [Output]
     * search result item
     * [Note]
     */
    public List<googleSearchResultItem> extractGoogleSearchResult(string googleSearchUrl = "", string googleSearchRespHtml = "")
    {
        List<googleSearchResultItem> resultItemList = new List<googleSearchResultItem>();

        //if not give html, get it
        if (string.IsNullOrEmpty(googleSearchRespHtml))
        {
            googleSearchRespHtml = crl.getUrlRespHtml_multiTry(googleSearchUrl);
        }

        if (!string.IsNullOrEmpty(googleSearchRespHtml))
        {
            //<li class="g">
            //    <div data-hveid="42" class="rc">
            //    <span style="float:left"></span>
            //    <h3 class="r">
            //        <a href="http://articles.timesofindia.indiatimes.com/2012-09-22/kochi/34021062_1_kidney-transplants-fireworks-factory-birthday-celebrations" onmousedown="return rwt(this,'','','','1','AFQjCNEML6Pgh2cKhjyy19S1Rj2zt91iAg','','0CCsQFjAA','','',event)" target="_blank">
            //            Amritanandamayi Math to <em>sponsor charity</em> events - Times Of India
            //        </a>
            //    </h3>

            //    <div class="s">
            //        <div><div class="f kv" style="white-space:nowrap"><cite class="bc">articles.timesofindia.indiatimes.com &rsaquo; <a href="http://articles.timesofindia.indiatimes.com/" onmousedown="return rwt(this,'','','','1','AFQjCNHYQDP9zOXmqE2BLyiniRDD4oZS4g','','0CC0Q6QUoADAA','','',event)" target="_blank">Collections</a> &rsaquo; <a href="http://articles.timesofindia.indiatimes.com/keyword/kannur" onmousedown="return rwt(this,'','','','1','AFQjCNFOec2KvR8ZCCt8sV5S5EZBpJ1l8g','','0CC4Q6QUoATAA','','',event)" target="_blank">Kannur</a></cite> - <a href="http://translate.google.com.hk/translate?hl=zh-CN&amp;sl=en&amp;u=http://articles.timesofindia.indiatimes.com/2012-09-22/kochi/34021062_1_kidney-transplants-fireworks-factory-birthday-celebrations&amp;prev=/search%3Fq%3Dweight%2Bloss%2B%2522Sponsor%2BCharity%2522%26newwindow%3D1%26safe%3Dstrict" onmousedown="return rwt(this,'','','','1','AFQjCNEiP3vOES7Rpw3v20GEzkxb_WL5DA','','0CDAQ7gEwAA','','',event)" target="_blank" class="fl">翻译此页</a></div><div class="f slp"></div><span class="st"><span class="f">2012年9月22日 &ndash; </span>Amritanandamayi Math to <em>sponsor charity</em> events. TNN Sep 22, 2012, <b>...</b> 10 Tips for guaranteed <em>weight loss</em> &middot; How to lose weight without dieting&nbsp;<b>...</b></span>
            //        </div>
            //    </div>
            //</div>
            //</li>

            //<li class="g">
            //    <div data-hveid="50" class="rc">
            //        <span style="float:left"></span>
            //        <h3 class="r">
            //            <a href="http://www.gobookee.net/non-profit-charity-golf-sponsor-letter/" onmousedown="return rwt(this,'','','','2','AFQjCNGACDpc3rYcQ7xyLWeso2O8Uh_dzQ','','0CDMQFjAB','','',event)" target="_blank">
            //                Non profit charity golf sponsor letter - free eBooks download
            //            </a>
            //        </h3>
            //        <div class="s"><div><div class="f kv" style="white-space:nowrap"><cite>www.gobookee.net/non-profit-charity-golf-sponsor-letter/</cite>‎<div class="action-menu ab_ctl"><a class="clickable-dropdown-arrow ab_button" id="am-b1" href="#" data-ved="0CDQQ7B0wAQ" aria-label="结果详情" jsaction="ab.tdd; keydown:ab.hbke; keypress:ab.mskpe" role="button" aria-haspopup="true" aria-expanded="false"><span class="mn-dwn-arw"></span></a><div data-ved="0CDUQqR8wAQ" class="action-menu-panel ab_dropdown" jsaction="keydown:ab.hdke; mouseover:ab.hdhne; mouseout:ab.hdhue" role="menu" tabindex="-1"><ul><li class="action-menu-item ab_dropdownitem" role="menuitem"><a href="http://webcache.googleusercontent.com/search?q=cache:700J2efn4woJ:www.gobookee.net/non-profit-charity-golf-sponsor-letter/+weight+loss+%22Sponsor+Charity%22&amp;cd=2&amp;hl=zh-CN&amp;ct=clnk&amp;gl=cn" onmousedown="return rwt(this,'','','','2','AFQjCNH4JkH1_ORT0Gq3Gi-_UsKhuGy4PA','','0CDYQIDAB','','',event)" target="_blank" class="fl">网页快照</a></li></ul></div></div><a href="http://translate.google.com.hk/translate?hl=zh-CN&amp;sl=en&amp;u=http://www.gobookee.net/non-profit-charity-golf-sponsor-letter/&amp;prev=/search%3Fq%3Dweight%2Bloss%2B%2522Sponsor%2BCharity%2522%26newwindow%3D1%26safe%3Dstrict" onmousedown="return rwt(this,'','','','2','AFQjCNFgq5X686zRjTuhe8rQ11RoE7VNEw','','0CDgQ7gEwAQ','','',event)" target="_blank" class="fl">翻译此页</a></div><div class="f slp"></div><span class="st">GOLF TOURNAMENT <em>SPONSOR. ... charity</em> golf tournament to help raise funds for our programs and teams ... non-profit org. so all donations/sponsorships are&nbsp;<b>...</b></span></div></div>
            //    </div>
            //</li>


            HtmlAgilityPack.HtmlDocument htmlDoc = crl.htmlToHtmlDoc(googleSearchRespHtml);
            HtmlNodeCollection liNodeList = htmlDoc.DocumentNode.SelectNodes("//li[@class='g']");
            foreach (HtmlNode liNode in liNodeList)
            {
                HtmlNode h3ANode = liNode.SelectSingleNode(".//h3[@class='r']/a");
                if (h3ANode != null)
                {
                    googleSearchResultItem singleResultItem = new googleSearchResultItem();

                    //string titleHtml = h3ANode.InnerHtml; //"Amritanandamayi Math to <em>sponsor charity</em> events - Times Of India"
                    string titleHtml = h3ANode.InnerText; //"Amritanandamayi Math to sponsor charity events - Times Of India"
                    string filteredTitle = crl.htmlRemoveTag(titleHtml);

                    string url = h3ANode.Attributes["href"].Value; //"http://articles.timesofindia.indiatimes.com/2012-09-22/kochi/34021062_1_kidney-transplants-fireworks-factory-birthday-celebrations"

                    string decoedTitle = HttpUtility.HtmlDecode(filteredTitle);
                    string decoedUrl = HttpUtility.HtmlDecode(url);

                    //store info
                    singleResultItem.Title = decoedTitle;
                    singleResultItem.Url = decoedUrl;

                    resultItemList.Add(singleResultItem);
                }
                else
                {
 
                }
            }
        }

        return resultItemList;
    }
}