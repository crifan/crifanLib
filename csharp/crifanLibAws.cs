/*
 * [File]
 * crifanLibAws.cs
 * 
 * [Function]
 * Crifan Lib, C# version, for Amazon, use AWS API
 * 
 * [Note]
 * 1.use crifanLib.cs
 * http://www.crifan.com/crifan_released_all/crifanlib/
 * http://www.crifan.com/crifan_csharp_lib_crifanlib_cs/
 * 2.use HtmlAgilityPack
 *  
 * [Version]
 * v1.6
 * 
 * [update]
 * 2013-07-04
 * 
 * [Author]
 * Crifan Li
 * 
 * [Contact]
 * http://www.crifan.com/contact_me/
 * 
 * [History]
 * [v1.6]
 * 1. update requestIsValid
 * 
 * [v1.5]
 * 1. update awsEndpoint
 * 
 * [v1.4]
 * 1. update to awsGetBrowseNodeLookupResp
 * 2. added extractSingleBrowseNode, extractBrowseNodeList
 * 
 * [v1.1]
 * 1. many updates
 * 
 * [v1.0]
 * 1. move from crifanLibAmazon.cs to here
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Web;

using NLog;
using NLog.Targets;
using NLog.Config;

using System.Net;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.XPath;

public class crifanLibAws
{
    public crifanLib crl;

    //for log
    public Logger gLogger = null;
    
    //AWS
    //http://www.crifan.com/how_to_use_amzon_aws_api_cn_version/
    public enum awsEndpoint
    {
        CA,
        CN,
        DE,
        ES,
        FR,
        IT,
        JP,
        UK,
        US
    }

    private Dictionary<awsEndpoint, string> awsEndpointDict;
    private string awsAccessKeyId;
    private string awsSecretKey;
    //added by Crifan Li
    //https://affiliate-program.amazon.co.uk/gp/advertising/api/detail/api-changes.html?ie=UTF8&pf_rd_t=501&ref_=amb_link_83388313_2&pf_rd_m=A3P5ROKL5A1OLE&pf_rd_p=&pf_rd_s=assoc-center-1&pf_rd_r=&pf_rd_i=assoc-api-detail-2-v2
    //Product Advertising API Change Details
    //Associate Tag Parameter: Every request made to the API should include a valid Associate Tag. Any request that does not contain a valid Associate Tag will be rejected with an appropriate error message. For details on the Associate Tag parameter, please refer to our Developer guide.
    //-> must add this Associate Tag, otherwise will return:
    //<Error>
    //    <Code>AWS.MissingParameters</Code>
    //    <Message>Your request is missing required parameters. Required parameters include AssociateTag.</Message>
    //</Error>
    private string awsAssociateTag;
    private awsEndpoint awsEndpointType;
    private string awsApiVersion;

    private string awsNamespace;
    private string awsEndPoint;

    private byte[] secretKeyByteArr;
    private HMAC hmacSha256Signer;
    
    private const string constStrRequestUri = "/onca/xml";
    private const string constStrRequestMethod = "GET";


    //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/BrowseNodeIDs.html
    //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/BrowseNodeLookup.html
    public struct awsBrowseNode
    {
        public string   Name            { get; set; }   //Appliances
        public string   BrowseNodeId    { get; set; }   //2619525011
        public string   IsCategoryRoot  { get; set; }   //1, can be null
    };

    public struct awsBrowseNodeLookupResp
    {
        //<BrowseNode>
        //    <BrowseNodeId>10304191</BrowseNodeId>
        //    <Name>Categories</Name>
        //    <IsCategoryRoot>1</IsCategoryRoot>
        //    <Ancestors>
        //        <BrowseNode>
        //            <BrowseNodeId>10272111</BrowseNodeId>
        //            <Name>Everything Else</Name>
        //        </BrowseNode>
        //    </Ancestors>
        //</BrowseNode>

        //<BrowseNode>
        //    <BrowseNodeId>2619525011</BrowseNodeId>
        //    <Name>Appliances</Name>
        //    <Children>
        //        <BrowseNode>
        //            <BrowseNodeId>2619526011</BrowseNodeId>
        //            <Name>Categories</Name>
        //            <IsCategoryRoot>1</IsCategoryRoot>
        //        </BrowseNode>
        //        <BrowseNode>
        //            <BrowseNodeId>2645269011</BrowseNodeId>
        //            <Name>Featured Categories</Name>
        //        </BrowseNode>
        //        <BrowseNode>
        //            <BrowseNodeId>2645372011</BrowseNodeId>
        //            <Name>Self Service</Name>
        //        </BrowseNode>
        //    </Children>
        //</BrowseNode>

        //public awsBrowseNode selfBrowseNode { get; set; } //self's BrowseNode
        public awsBrowseNode selfBrowseNode; //self's BrowseNode
        public List<awsBrowseNode> Ancestors { get; set; }  // can be null
        public List<awsBrowseNode> Children { get; set; }   // can be null
    };

    public struct awsSearchResultItem
    {
        public string Asin { get; set; }
        public string ParentAsin { get; set; }
    }

    public struct awsSearchResultInfo
    {
        public string TotalResults { get; set; }
        public string TotalPages { get; set; }
        public string MoreSearchResultsUrl { get; set; }
        public List<awsSearchResultItem> SearchResultItemList { get; set; }
    };

    //for item dimenson and package dimension
    public struct awsProductDimension
    {
        public string LengthHundredthsInch { get; set; } //inches
        public string WidthHundredthsInch { get; set; } //inches
        public string HeightHundredthsInch { get; set; } //inches

        public string WeightPound { get; set; } //pounds
    };

    public struct awsListPrice
    {
        public string Amount { get; set; } //19900
        public string CurrencyCode { get; set; } //USD
        public string FormattedPrice { get; set; } //$199.00
    };

    public struct awsItemAttributes
    {
        public string Asin { get; set; } //B0083PWAPW
        public string ParentAsin { get; set; } //B008GGCAVM

        //public string Binding { get; set; }
        //public string Brand { get; set; } //Amazon Digital Services Inc.

        public List<string> FeatureList { get; set; } //may have 0 - ? features/bullets

        //public awsItemDimension ItemDimension { get; set; }
        public awsProductDimension itemDimensions;
        public awsProductDimension packageDimensions;

        //public string Label { get; set; }

        //public awsListPrice ListPrice { get; set; }
        public awsListPrice listPrice;

        public string Manufacturer { get; set; }
        public string Title { get; set; } //Kindle Fire HD 7", Dolby Audio, Dual-Band Wi-Fi, 16 GB - Includes Special Offers
    };

    public struct awsOffersInfo
    {
        public string Asin { get; set; } //

        public string TotalOffers { get; set; }
        public string TotalOfferPages { get; set; }

        public string TotalNew { get; set; }
        public string TotalUsed { get; set; }
        public string TotalCollectible { get; set; }
        public string TotalRefurbished { get; set; }

        //public string Amount { get; set; }
        //public string Availability { get; set; }
        //public string Name { get; set; }
    };

    //Offer -> Price
    public struct awsPrice
    {
        public string Amount { get; set; }
        public string CurrencyCode { get; set; }
        public string FormattedPrice { get; set; }
    }


    public struct awsOffer
    {
        //https://affiliate-program.amazon.co.uk/gp/advertising/api/detail/api-changes.html?ie=UTF8&pf_rd_t=501&ref_=amb_link_83388313_2&pf_rd_m=A3P5ROKL5A1OLE&pf_rd_p=&pf_rd_s=assoc-center-1&pf_rd_r=&pf_rd_i=assoc-api-detail-2-v2
        //public string MerchantId { get; set; }

        public string MerchantName { get; set; }

        public awsPrice Price { get; set; }
    }

    public struct awsOfferFullInfo
    {
        public string Asin { get; set; }

        public List<awsOffer> offerList { get; set; }

        public string TotalOffers { get; set; }
        public string TotalOfferPages { get; set; }

        public string TotalNew { get; set; }
        public string TotalUsed { get; set; }
        public string TotalCollectible { get; set; }
        public string TotalRefurbished { get; set; }

        //public string Amount { get; set; }
        //public string Availability { get; set; }
        //public string Name { get; set; }

    };

    public struct awsEditorialReview
    {
        public string Asin { get; set; }

        public string Source { get; set; }
        public string Content { get; set; }
    };

    public struct awsImageItem
    {
        public string Url { get; set; }

        public string HeightPixel { get; set; }
        public string WidthPixel { get; set; }
    }

    public struct awsImages
    {
        public string Asin { get; set; }

        //public List<string> SmallImage { get; set; }
        //public List<string> MediumImage { get; set; }
        public List<awsImageItem> LargeImageList { get; set; }

    };

    //find global defaut (current using) logger
    public crifanLibAws()
    {
        //!!! for load embedded dll: (1) register resovle handler
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

        //init something
        crl = new crifanLib();

        gLogger = LogManager.GetLogger("");

        awsEndpointDict = buildEndpointDict();
    }

    //specify your logger
    public crifanLibAws(Logger logger)
    {
        //!!! for load embedded dll: (1) register resovle handler
        AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

        //init something
        crl = new crifanLib();
        
        gLogger = logger;

        awsEndpointDict = buildEndpointDict();
    }

    private Dictionary<awsEndpoint, string> buildEndpointDict()
    {
        //old
        /*
        * The destination is the service end-point for your application:
        *  US: ecs.amazonaws.com
        *  JP: ecs.amazonaws.jp
        *  UK: ecs.amazonaws.co.uk
        *  DE: ecs.amazonaws.de
        *  FR: ecs.amazonaws.fr
        *  CA: ecs.amazonaws.ca
        */

        //new
        //http://www.crifan.com/how_to_use_amzon_aws_api_cn_version/
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/AnatomyOfaRESTRequest.html#EndpointsandWebServices
        //Locale  Endpoint
        //CA      webservices.amazon.ca
        //CN      webservices.amazon.cn
        //DE      webservices.amazon.de
        //ES      webservices.amazon.es
        //FR      webservices.amazon.fr
        //IT      webservices.amazon.it
        //JP      webservices.amazon.co.jp
        //UK      webservices.amazon.co.uk
        //US      webservices.amazon.com

        Dictionary<awsEndpoint, string> endpointDict = new Dictionary<awsEndpoint, string>();
        endpointDict.Add(awsEndpoint.CA, "webservices.amazon.ca");
        endpointDict.Add(awsEndpoint.CN, "webservices.amazon.cn");
        endpointDict.Add(awsEndpoint.DE, "webservices.amazon.de");
        endpointDict.Add(awsEndpoint.ES, "webservices.amazon.es");
        endpointDict.Add(awsEndpoint.FR, "webservices.amazon.fr");
        endpointDict.Add(awsEndpoint.IT, "webservices.amazon.it");
        endpointDict.Add(awsEndpoint.JP, "webservices.amazon.co.jp");
        endpointDict.Add(awsEndpoint.UK, "webservices.amazon.co.uk");
        endpointDict.Add(awsEndpoint.US, "webservices.amazon.com");

        return endpointDict;
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

    /********************************* AWS API *******************************/

    /*********************************  helper functions *********************************/
    /*
     * To help the SortedDictionary order the name-value pairs in the correct way.
     */
    class ParamComparer : IComparer<string>
    {
        public int Compare(string p1, string p2)
        {
            return string.CompareOrdinal(p1, p2);
        }
    }

    /*
        * Sign a request in the form of a Dictionary of name-value pairs.
        * 
        * This method returns a complete URL to use. Modifying the returned URL
        * in any way invalidates the signature and Amazon will reject the requests.
        */
    public string Sign(IDictionary<string, string> request)
    {
        // Use a SortedDictionary to get the parameters in naturual byte order, as
        // required by AWS.
        ParamComparer paraCmp = new ParamComparer();
        SortedDictionary<string, string> sortedMap = new SortedDictionary<string, string>(request, paraCmp);

        // Add the AWSAccessKeyId and Timestamp to the requests.
        sortedMap["AWSAccessKeyId"] = this.awsAccessKeyId;

        //added by Crifan Li
        sortedMap["AssociateTag"] = this.awsAssociateTag;

        sortedMap["Timestamp"] = this.GetTimestamp();

        // Get the canonical query string
        string canonicalQS = this.ConstructCanonicalQueryString(sortedMap);

        // Derive the bytes needs to be signed.
        StringBuilder builder = new StringBuilder();
        builder.Append(constStrRequestMethod)
            .Append("\n")
            .Append(this.awsEndPoint)
            .Append("\n")
            .Append(constStrRequestUri)
            .Append("\n")
            .Append(canonicalQS);

        string stringToSign = builder.ToString();
        byte[] toSign = Encoding.UTF8.GetBytes(stringToSign);

        // Compute the signature and convert to Base64.
        byte[] sigBytes = hmacSha256Signer.ComputeHash(toSign);
        string signature = Convert.ToBase64String(sigBytes);

        // now construct the complete URL and return to caller.
        StringBuilder qsBuilder = new StringBuilder();
        qsBuilder.Append("http://")
            .Append(this.awsEndPoint)
            .Append(constStrRequestUri)
            .Append("?")
            .Append(canonicalQS)
            .Append("&Signature=")
            .Append(this.PercentEncodeRfc3986(signature));

        return qsBuilder.ToString();
    }

    /*
        * Sign a request in the form of a query string.
        * 
        * This method returns a complete URL to use. Modifying the returned URL
        * in any way invalidates the signature and Amazon will reject the requests.
        */
    public string Sign(string queryString)
    {
        IDictionary<string, string> request = this.CreateDictionary(queryString);
        return this.Sign(request);
    }

    /*
        * Current time in IS0 8601 format as required by Amazon
        */
    private string GetTimestamp()
    {
        DateTime currentTime = DateTime.UtcNow;
        string timestamp = currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        return timestamp; //"2013-06-14T13:33:33Z"
    }

    /*
        * Percent-encode (URL Encode) according to RFC 3986 as required by Amazon.
        * 
        * This is necessary because .NET's HttpUtility.UrlEncode does not encode
        * according to the above standard. Also, .NET returns lower-case encoding
        * by default and Amazon requires upper-case encoding.
        */
    private string PercentEncodeRfc3986(string str)
    {
        str = HttpUtility.UrlEncode(str, System.Text.Encoding.UTF8);
        str = str.Replace("'", "%27").Replace("(", "%28").Replace(")", "%29").Replace("*", "%2A").Replace("!", "%21").Replace("%7e", "~").Replace("+", "%20");

        StringBuilder sbuilder = new StringBuilder(str);
        for (int i = 0; i < sbuilder.Length; i++)
        {
            if (sbuilder[i] == '%')
            {
                if (Char.IsLetter(sbuilder[i + 1]) || Char.IsLetter(sbuilder[i + 2]))
                {
                    sbuilder[i + 1] = Char.ToUpper(sbuilder[i + 1]);
                    sbuilder[i + 2] = Char.ToUpper(sbuilder[i + 2]);
                }
            }
        }
        return sbuilder.ToString();
    }

    /*
        * Convert a query string to corresponding dictionary of name-value pairs.
        */
    private IDictionary<string, string> CreateDictionary(string queryString)
    {
        Dictionary<string, string> map = new Dictionary<string, string>();

        string[] requestParams = queryString.Split('&');

        for (int i = 0; i < requestParams.Length; i++)
        {
            if (requestParams[i].Length < 1)
            {
                continue;
            }

            char[] sep = { '=' };
            string[] param = requestParams[i].Split(sep, 2);
            for (int j = 0; j < param.Length; j++)
            {
                param[j] = HttpUtility.UrlDecode(param[j], System.Text.Encoding.UTF8);
            }
            switch (param.Length)
            {
                case 1:
                    {
                        if (requestParams[i].Length >= 1)
                        {
                            if (requestParams[i].ToCharArray()[0] == '=')
                            {
                                map[""] = param[0];
                            }
                            else
                            {
                                map[param[0]] = "";
                            }
                        }
                        break;
                    }
                case 2:
                    {
                        if (!string.IsNullOrEmpty(param[0]))
                        {
                            map[param[0]] = param[1];
                        }
                    }
                    break;
            }
        }

        return map;
    }

    /*
        * Consttuct the canonical query string from the sorted parameter map.
        */
    private string ConstructCanonicalQueryString(SortedDictionary<string, string> sortedParamMap)
    {
        StringBuilder builder = new StringBuilder();

        if (sortedParamMap.Count == 0)
        {
            builder.Append("");
            return builder.ToString();
        }

        foreach (KeyValuePair<string, string> kvp in sortedParamMap)
        {
            builder.Append(this.PercentEncodeRfc3986(kvp.Key));
            builder.Append("=");
            builder.Append(this.PercentEncodeRfc3986(kvp.Value));
            builder.Append("&");
        }
        string canonicalString = builder.ToString();
        canonicalString = canonicalString.Substring(0, canonicalString.Length - 1);
        return canonicalString;
    }

    /*********************************  AWS functions *********************************/

    public void initAws(
        string accessKeyId,
        string secretKey,
        string associateTag,
        awsEndpoint endpoint,
        string apiVersion = "2011-08-01")
    {
        //get input para
        awsAccessKeyId = accessKeyId;
        awsSecretKey = secretKey;
        awsAssociateTag = associateTag;
        awsEndpointType = endpoint;
        awsApiVersion = apiVersion;

        //init related
        awsNamespace = "http://webservices.amazon.com/AWSECommerceService/" + awsApiVersion;

        string endpointStr = "";
        if (awsEndpointDict.TryGetValue(awsEndpointType, out endpointStr))
        {
            awsEndPoint = endpointStr;
        }

        secretKeyByteArr = Encoding.UTF8.GetBytes(awsSecretKey);
        hmacSha256Signer = new HMACSHA256(secretKeyByteArr);
    }

    /*
     * [Function]
     * check whether request is valid
     * [Input]
     * current node contain:
     * <Request>
     *   <IsValid>True</IsValid>
     *   ... 
     * </Request>
     * 
     * [Output]
     * is valid or not
     * 
     * [Note]
     */
    public bool requestIsValid(XmlNode respXmlNode)
    {
        bool isValid = false;

        if (respXmlNode != null)
        {
            //<Request>
            //    <IsValid>True</IsValid>
            //    <BrowseNodeLookupRequest>
            //        <BrowseNodeId>2619525011</BrowseNodeId>
            //        <ResponseGroup>BrowseNodeInfo</ResponseGroup>
            //    </BrowseNodeLookupRequest>
            //</Request>

            XmlNode requestdNode = respXmlNode.SelectSingleNode("./Request");
            if (requestdNode != null)
            {
                XmlNode isValidNode = requestdNode.SelectSingleNode("./IsValid");

                string strIsValid = isValidNode.InnerText;
                if (strIsValid.Equals("True", StringComparison.CurrentCultureIgnoreCase))
                {
                    //<BrowseNodes>
                    //    <Request>
                    //        <IsValid>True</IsValid>
                    //        <BrowseNodeLookupRequest>
                    //            <BrowseNodeId>2617941011 </BrowseNodeId>
                    //            <ResponseGroup>BrowseNodeInfo</ResponseGroup>
                    //        </BrowseNodeLookupRequest>
                    //        <Errors>
                    //            <Error>
                    //                <Code>AWS.InvalidParameterValue</Code>
                    //                <Message>2617941011  is not a valid value for BrowseNodeId. Please change this value and retry your request.</Message>
                    //            </Error>
                    //        </Errors>
                    //    </Request>

                    XmlNode errorsErrorNode = requestdNode.SelectSingleNode("./Errors/Error");
                    if (errorsErrorNode != null)
                    {
                        XmlNode errorCodeNode = errorsErrorNode.SelectSingleNode("./Code");
                        XmlNode errorMessageNode = errorsErrorNode.SelectSingleNode("./Message");
                        gLogger.Debug(String.Format("Request valid, but Error: Code={0}, Message={1}", errorCodeNode.InnerText, errorMessageNode.InnerText));
                    }
                    else
                    {
                        isValid = true;                    
                    }
                }
                else
                {
                    //gLogger.Debug(String.Format("Request not valid for {0}, IsValid={1}", respXmlNode.ToString(), strIsValid));
                    gLogger.Debug(String.Format("Request IsValid={0} for {1}, ", strIsValid, respXmlNode.InnerXml));
                }
            }
            else
            {
                gLogger.Debug("not found Request/IsValid for respXmlNode=" + respXmlNode.ToString());
            }
        }

        return isValid;
    }

    //just for:
    //sometime, getUrlRespHtml_multiTry from amazon will fail, no response
    //->maybe some network is not stable, maybe amazon access frequence has some limit
    //-> so here to wait sometime to re-do it
    private string _getUrlRespHtml_multiTry_multiTry(string awsReqUrl, int maxTryNum = 10)
    {
        string respHtml = "";

        for (int tryIdx = 0; tryIdx < maxTryNum; tryIdx++)
        {
            respHtml = crl.getUrlRespHtml_multiTry(awsReqUrl, maxTryNum: maxTryNum);
            if (respHtml != "")
            {
                break;
            }
            else
            {
                //something wrong
                //maybe network is not stable
                //so wait some time, then re-do it
                System.Threading.Thread.Sleep(200); //200 ms
            }
        }

        return respHtml;
    }


    /*
     * [Function]
     * aws request url to xml doc, no xmlns version
     * [Input]
     * aws request url
     * "http://ecs.amazonaws.com/onca/xml?AWSAccessKeyId=xxx&AssociateTag=xxx&BrowseNodeId=2619525011&Operation=BrowseNodeLookup&ResponseGroup=BrowseNodeInfo&Service=AWSECommerceService&Timestamp=2013-06-14T15%3A10%3A14Z&Version=2011-08-01&Signature=2KN%2Fa%2BV66sIUGNXianeZ7k7aqIzvA4pgFuh2DX4ygtY%3D"
     * 
     * [Output]
     * xml doc, no xmlns
     * 
     * [Note]
     */
    public XmlDocument awsReqUrlToXmlDoc_noXmlns(string awsReqUrl)
    {
        XmlDocument xmlDocNoXmlns = new XmlDocument();

        //string respHtml = crl.getUrlRespHtml_multiTry(awsReqUrl, maxTryNum:20);
        string respHtml = _getUrlRespHtml_multiTry_multiTry(awsReqUrl, maxTryNum:100);
        string xmlnsStr = " xmlns=\"" + awsNamespace + "\""; //"http://webservices.amazon.com/AWSECommerceService/2011-08-01"
        string xmlNoXmlns = respHtml.Replace(xmlnsStr, "");
        if (!string.IsNullOrEmpty(xmlNoXmlns))
        {
            xmlDocNoXmlns.LoadXml(xmlNoXmlns);
        }
        else
        {
            //special:
            //when request too much and too frequently, maybe errror, such as when :
            //"http://ecs.amazonaws.com/onca/xml?AWSAccessKeyId=AKIAJQAUAH2R4HCG63LQ&AssociateTag=crifancom-20&BrowseNode=3741411&ItemPage=6&Operation=ItemSearch&ResponseGroup=ItemIds&SearchIndex=Appliances&Service=AWSECommerceService&Timestamp=2013-06-14T16%3A40%3A24Z&Version=2011-08-01&Signature=cw3Al9pxqj1d5II8dN3VeyU5DPxQhIZiDYjLPLIA86A%3D"
            //return empty respHtml

            gLogger.Debug("can not get valid respHtml for awsReqUrl=" + awsReqUrl);
        }

        return xmlDocNoXmlns;
    }

    /*
     * [Function]
     * aws request url to xml doc, with xmlns version
     * [Input]
     * aws request url
     * 
     * [Output]
     * xml doc, with xmlns
     * 
     * [Note]
     */
    public XmlDocument awsReqUrlToXmlDoc_WithXmlns(string awsReqUrl)
    {
        XmlDocument xmlDocWithXmlns = new XmlDocument();

        //method 1: use WebRequest and WebResponse
        //WebRequest request = HttpWebRequest.Create(awsReqUrl);
        //WebResponse response = request.GetResponse();
        //XmlDocument doc = new XmlDocument();
        //doc.Load(response.GetResponseStream());

        //method 2: use my getUrlRespHtml_multiTry
        //string respHtml = crl.getUrlRespHtml_multiTry(awsReqUrl);
        string respHtml = _getUrlRespHtml_multiTry_multiTry(awsReqUrl);

        xmlDocWithXmlns.LoadXml(respHtml);

        //XmlNamespaceManager nsmgr = new XmlNamespaceManager(xmlDocWithXmlns.NameTable);
        //nsmgr.AddNamespace("ams", awsNamespace);
        //XmlNode browseNodesNode = xmlDocWithXmlns.SelectSingleNode("/ams:BrowseNodeLookupResponse/ams:BrowseNodes", nsmgr);

        return xmlDocWithXmlns;
    }

    /*
     * [Function]
     * extract browse node info
     * [Input]
     * an xml node, contain browser node info
     * eg:
     *  <BrowseNode>
     *      <BrowseNodeId>10272111</BrowseNodeId>
     *      <Name>Everything Else</Name>
     *  </BrowseNode>
     *  
     * <BrowseNode>
     *      <BrowseNodeId>10304191</BrowseNodeId>
     *      <Name>Categories</Name>
     *      <IsCategoryRoot>1</IsCategoryRoot>
     * 
     * [Output]
     * extracted awsBrowseNode
     * 
     * [Note]
     */
    public awsBrowseNode extractSingleBrowseNode(XmlNode curBrowseNode, bool bAutoHtmlDecode = true)
    {
        awsBrowseNode extractedBrowseNode = new awsBrowseNode();
        
        //1. BrowseNodeId
        XmlNode browseNodeIdNode            = curBrowseNode.SelectSingleNode("./BrowseNodeId");
        extractedBrowseNode.BrowseNodeId    = browseNodeIdNode.InnerText;
        if(bAutoHtmlDecode)
        {
            //special:
            //<BrowseNode>
            //    <BrowseNodeId>3741181</BrowseNodeId>
            //    <Name>Parts &amp; Accessories</Name>
            //</BrowseNode>

            //note: it seems that, when xml.Load, then already do this html decode
            //-> here already got html decoded content 
            //-> no need do html decode again 
            //-> here still do html code 
            //-> just to makesure is html decoded

            extractedBrowseNode.BrowseNodeId = HttpUtility.HtmlDecode(extractedBrowseNode.BrowseNodeId);
        }

        //1. Name
        XmlNode nameNode            = curBrowseNode.SelectSingleNode("./Name");
        extractedBrowseNode.Name    = nameNode.InnerText;
        if(bAutoHtmlDecode)
        {
            extractedBrowseNode.Name = HttpUtility.HtmlDecode(extractedBrowseNode.Name);
        }

        //3. IsCategoryRoot
        XmlNode isCategoryRootNode  = curBrowseNode.SelectSingleNode("./IsCategoryRoot");
        if(isCategoryRootNode != null)
        {
            extractedBrowseNode.IsCategoryRoot = isCategoryRootNode.InnerText;

            if(bAutoHtmlDecode)
            {
                extractedBrowseNode.IsCategoryRoot = HttpUtility.HtmlDecode(extractedBrowseNode.IsCategoryRoot);
            }
        }

        return extractedBrowseNode;
    }


    /*
     * [Function]
     * extract browse node list
     * [Input]
     * an xml node, can be Children or Ancestors, contain browser node list
     * eg:
     * <Children>
     *     <BrowseNode>
     *         <BrowseNodeId>2619526011</BrowseNodeId>
     *         <Name>Categories</Name>
     *         <IsCategoryRoot>1</IsCategoryRoot>
     *     </BrowseNode>
     *     <BrowseNode>
     *         <BrowseNodeId>2645269011</BrowseNodeId>
     *         <Name>Featured Categories</Name>
     *     </BrowseNode>
     *     <BrowseNode>
     *         <BrowseNodeId>2645372011</BrowseNodeId>
     *         <Name>Self Service</Name>
     *     </BrowseNode>
     * </Children>
     *  
     * <Ancestors>
     *     <BrowseNode>
     *         <BrowseNodeId>10272111</BrowseNodeId>
     *         <Name>Everything Else</Name>
     *     </BrowseNode>
     * </Ancestors>
     * 
     * [Output]
     * extracted awsBrowseNode list
     * 
     * [Note]
     */
    public List<awsBrowseNode> extractBrowseNodeList(XmlNode curParentLevelNode)
    {
        List<awsBrowseNode> extractedBrowseNodeList = new List<awsBrowseNode>();

        if(curParentLevelNode != null)
        {
            XmlNodeList subBrowseNodeList = curParentLevelNode.SelectNodes("./BrowseNode");
            if((subBrowseNodeList != null) && (subBrowseNodeList.Count > 0))
            {
                foreach(XmlNode subBrowseNode in subBrowseNodeList)
                {
                    awsBrowseNode eachSubBrowseNode = extractSingleBrowseNode(subBrowseNode);
                    extractedBrowseNodeList.Add(eachSubBrowseNode);
                }
            }
        }
        else
        {
            extractedBrowseNodeList = null;
        }

        return extractedBrowseNodeList;
    }

    /*
     * [Function]
     * aws browse node id
     * [Input]
     * browser node id
     * eg:
     * root category: 2619525011
     * sub category: 3737671
     * 
     * [Output]
     * BrowseNodeLookup responsed BrowseNodeInfo
     * 
     * [Note]
     */
    public awsBrowseNodeLookupResp awsGetBrowseNodeLookupResp(string currentBrowseNodeId)
    {
        awsBrowseNodeLookupResp browseNodeLookupResp = new awsBrowseNodeLookupResp();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "BrowseNodeLookup";
        reqDict["BrowseNodeId"] = currentBrowseNodeId;
        reqDict["ResponseGroup"] = "BrowseNodeInfo";

        String awsReqUrl = Sign(reqDict);

        //<BrowseNodeLookupResponse xmlns="http://webservices.amazon.com/AWSECommerceService/2011-08-01">
        //    <OperationRequest>
        //        ......
        //    </OperationRequest>
        //    <BrowseNodes>
        //        <Request>
        //            <IsValid>True</IsValid>
        //            <BrowseNodeLookupRequest>
        //                <BrowseNodeId>2619525011</BrowseNodeId>
        //                <ResponseGroup>BrowseNodeInfo</ResponseGroup>
        //            </BrowseNodeLookupRequest>
        //        </Request>
        //        <BrowseNode>
        //            <BrowseNodeId>2619525011</BrowseNodeId>
        //            <Name>Appliances</Name>
        //            <Children>
        //                <BrowseNode>
        //                    <BrowseNodeId>2619526011</BrowseNodeId>
        //                    <Name>Categories</Name>
        //                    <IsCategoryRoot>1</IsCategoryRoot>
        //                </BrowseNode>
        //                <BrowseNode>
        //                    <BrowseNodeId>2645269011</BrowseNodeId>
        //                    <Name>Featured Categories</Name>
        //                </BrowseNode>
        //                <BrowseNode>
        //                    <BrowseNodeId>2645372011</BrowseNodeId>
        //                    <Name>Self Service</Name>
        //                </BrowseNode>
        //            </Children>
        //        </BrowseNode>
        //    </BrowseNodes>
        //</BrowseNodeLookupResponse>

        //special: no children
        //<BrowseNodes>
        //    <Request>
        //        <IsValid>True</IsValid>
        //        <BrowseNodeLookupRequest>
        //            <BrowseNodeId>10304191</BrowseNodeId>
        //            <ResponseGroup>BrowseNodeInfo</ResponseGroup>
        //        </BrowseNodeLookupRequest>
        //    </Request>
        //    <BrowseNode>
        //        <BrowseNodeId>10304191</BrowseNodeId>
        //        <Name>Categories</Name>
        //        <IsCategoryRoot>1</IsCategoryRoot>
        //        <Ancestors>
        //            <BrowseNode>
        //                <BrowseNodeId>10272111</BrowseNodeId>
        //                <Name>Everything Else</Name>
        //            </BrowseNode>
        //        </Ancestors>
        //    </BrowseNode>
        //</BrowseNodes>

        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        XmlNode browseNodesNode = xmlDocNoXmlns.SelectSingleNode("/BrowseNodeLookupResponse/BrowseNodes");
        if (browseNodesNode != null)
        {
            if (requestIsValid(browseNodesNode))
            {
                XmlNode browseNodeNode = browseNodesNode.SelectSingleNode("./BrowseNode");
                if (browseNodeNode != null)
                {
                    //1. BrowseNodeId
                    //2. Name
                    //3. IsCategoryRoot
                    browseNodeLookupResp.selfBrowseNode = extractSingleBrowseNode(browseNodeNode);

                    //4. Ancestors
                    XmlNode ancestorsNode = browseNodeNode.SelectSingleNode("./Ancestors");
                    browseNodeLookupResp.Ancestors = extractBrowseNodeList(ancestorsNode);

                    //5. Children
                    XmlNode childrenNode = browseNodeNode.SelectSingleNode("./Children");
                    browseNodeLookupResp.Children = extractBrowseNodeList(childrenNode);
                }
                else
                {
                    gLogger.Debug("not found BrowseNodes/BrowseNode for currentBrowseNodeId=" + currentBrowseNodeId);
                }
            }
        }
        else
        {
            //something wrong
            gLogger.Debug("not found /BrowseNodeLookupResponse/BrowseNodes for browser node ID=" + currentBrowseNodeId);
        }

        return browseNodeLookupResp;
    }

    /*
     * [Function]
     * for single browser node, do search, get matched items
     * [Input]
     * (sub/child) browser node id
     * eg:
     * sub browser node id: 3737671
     * 
     * [Output]
     * search result item list
     * 
     * [Note]
     */
    public awsSearchResultInfo awsGetBrowserNodeSearchResultItemList(
        string subBrowserNodeId,
        string searchIndex,
        string itemPage = "1")
    {
        //List<awsSearchResultItem> awsSearchResultItemList = new List<awsSearchResultItem>();
        awsSearchResultInfo itemSearchResultInfo = new awsSearchResultInfo();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemSearch";
        reqDict["ResponseGroup"] = "ItemIds";

        //!!! not BrowseNodeId -> is BrowseNode
        //reqDict["BrowseNodeId"] = subBrowserNodeId; //"3737671"
        reqDict["BrowseNode"] = subBrowserNodeId; //"3737671"

        //means the root browser node name
        reqDict["SearchIndex"] = searchIndex; //"Appliances"

        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/ItemSearch.html
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/AvailabilityParameter.html
        reqDict["Availability"] = "Available";
        reqDict["Condition"] = "All";
        

        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/ItemSearch.html
        //The maximum ItemPage number that can be returned is 10.
        reqDict["ItemPage"] = itemPage;

        String awsReqUrl = Sign(reqDict);

        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        //<?xml version="1.0" ?>
        //<ItemSearchResponse xmlns="http://webservices.amazon.com/AWSECommerceService/2011-08-01">
        //    <OperationRequest>
        //        ......
        //    </OperationRequest>
        //    <Items>
        //        <Request>
        //            <IsValid>True</IsValid>
        //            <ItemSearchRequest>
        //                <BrowseNode>3737671</BrowseNode>
        //                <ResponseGroup>ItemIds</ResponseGroup>
        //                <SearchIndex>Appliances</SearchIndex>
        //            </ItemSearchRequest>
        //        </Request>
        //        <TotalResults>9539</TotalResults>
        //        <TotalPages>954</TotalPages>
        //        <MoreSearchResultsUrl>http://www.amazon.com/gp/redirect.html?camp=2025&amp;creative=386001&amp;location=http%3A%2F%2Fwww.amazon.com%2Fgp%2Fsearch%3Fnode%3D3737671%26url%3Dsearch-alias%253Dappliances&amp;linkCode=xm2&amp;tag=crifancom-20&amp;SubscriptionId=AKIAJQAUAH2R4HCG63LQ</MoreSearchResultsUrl>
        //        <Item>
        //            <ASIN>B003F4TH6G</ASIN>
        //            <ParentASIN>B00B2R5QPO</ParentASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B000R48G5K</ASIN>
        //            <ParentASIN>B007YJU30C</ParentASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B00162723O</ASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B00549DULS</ASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B0073HPU6M</ASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B0036WTWCQ</ASIN>
        //            <ParentASIN>B00B2R7ACG</ParentASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B00009W3G7</ASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B004K43I2Y</ASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B004P8K39Q</ASIN>
        //            <ParentASIN>B00B2R63OM</ParentASIN>
        //        </Item>
        //        <Item>
        //            <ASIN>B00B2BTAV6</ASIN>
        //        </Item>
        //    </Items>
        //</ItemSearchResponse>

        if (xmlDocNoXmlns != null)
        {
            XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemSearchResponse/Items");
            if (itemsNode != null)
            {
                if (requestIsValid(itemsNode))
                {
                    XmlNode totalResultsNode = itemsNode.SelectSingleNode("./TotalResults");
                    if (totalResultsNode != null)
                    {
                        itemSearchResultInfo.TotalResults = totalResultsNode.InnerText; //"9541"
                    }

                    XmlNode totalPagesNode = itemsNode.SelectSingleNode("./TotalPages");
                    if (totalPagesNode != null)
                    {
                        itemSearchResultInfo.TotalPages = totalPagesNode.InnerText; //"955"
                    }

                    XmlNode moreSearchResultsUrlNode = itemsNode.SelectSingleNode("./MoreSearchResultsUrl");
                    if (moreSearchResultsUrlNode != null)
                    {
                        itemSearchResultInfo.MoreSearchResultsUrl = moreSearchResultsUrlNode.InnerText; //"http://www.amazon.com/gp/redirect.html?camp=2025&creative=386001&location=http%3A%2F%2Fwww.amazon.com%2Fgp%2Fsearch%3Fnode%3D3737671%26url%3Dsearch-alias%253Dappliances&linkCode=xm2&tag=crifancom-20&SubscriptionId=AKIAJQAUAH2R4HCG63LQ"
                        itemSearchResultInfo.MoreSearchResultsUrl = HttpUtility.HtmlDecode(itemSearchResultInfo.MoreSearchResultsUrl); // seems that, when doc.XmlLod, already do htmlDecode -> here is already decoded html ?
                    }

                    XmlNodeList itemNodeList = itemsNode.SelectNodes("./Item");
                    if ((itemNodeList != null) && (itemNodeList.Count > 0))
                    {
                        itemSearchResultInfo.SearchResultItemList = new List<awsSearchResultItem>();

                        foreach (XmlNode itemNode in itemNodeList)
                        {
                            awsSearchResultItem singleResultItem = new awsSearchResultItem();

                            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
                            if (asinNode != null)
                            {
                                singleResultItem.Asin = asinNode.InnerText;
                            }
                            else
                            {
                                gLogger.Debug(String.Format("not found ./ASIN for sitemNode={1}", itemNode.ToString()));
                            }

                            XmlNode parentAsinNode = itemNode.SelectSingleNode("./ParentASIN");
                            if (parentAsinNode != null)
                            {
                                singleResultItem.ParentAsin = parentAsinNode.InnerText;
                            }

                            itemSearchResultInfo.SearchResultItemList.Add(singleResultItem);
                        }
                    }
                }
            }
            else
            {
                //something wrong
                gLogger.Debug(String.Format("not found /ItemSearchResponse/Items for subBrowserNodeId={0}, searchIndex={1}", subBrowserNodeId, searchIndex));
            }
        }

        return itemSearchResultInfo;
    }

    /*
     * [Function]
     * find variation item list for single asin
     * [Input]
     * single asin
     * eg:
     * B00B2R5QPO
     * B003F4TH6G
     * 
     * [Output]
     * variation item list
     * 
     * [Note]
     * 1. if not variation, then self is a single variation, will added into variation item list
     */
    public List<awsSearchResultItem> awsGetVariationItemList(string itemAsin)
    {
        List<awsSearchResultItem> variationItemList = new List<awsSearchResultItem>();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        reqDict["ResponseGroup"] = "Variations";

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        //if no variation
        //<Items>
        //    <Request>
        //        <IsValid>True</IsValid>
        //        <ItemLookupRequest>
        //            <IdType>ASIN</IdType>
        //            <ItemId>B003F4TH6G</ItemId>
        //            <ResponseGroup>Variations</ResponseGroup>
        //            <VariationPage>All</VariationPage>
        //        </ItemLookupRequest>
        //    </Request>
        //    <Item>
        //        <ASIN>B003F4TH6G</ASIN>
        //        <ParentASIN>B00B2R5QPO</ParentASIN>
        //    </Item>
        //</Items>

        //if has variation
        //<Item>
        //    <ASIN>B00B2R5QPO</ASIN>
        //    <ParentASIN>B00B2R5QPO</ParentASIN>
        //    <VariationSummary>
        //        <LowestPrice>
        //            <Amount>10999</Amount>
        //            <CurrencyCode>USD</CurrencyCode>
        //            <FormattedPrice>$109.99</FormattedPrice>
        //        </LowestPrice>
        //        <HighestPrice>
        //            <Amount>28599</Amount>
        //            <CurrencyCode>USD</CurrencyCode>
        //            <FormattedPrice>$285.99</FormattedPrice>
        //        </HighestPrice>
        //    </VariationSummary>
        //    <Variations>
        //        <TotalVariations>1</TotalVariations>
        //        <TotalVariationPages>1</TotalVariationPages>
        //        <VariationDimensions>
        //            <VariationDimension>Color</VariationDimension>
        //        </VariationDimensions>
        //        <Item>
        //            <ASIN>B003F4TH6G</ASIN>
        //            <ParentASIN>B00B2R5QPO</ParentASIN>
        //            <SmallImage>
        //                <URL>http://ecx.images-amazon.com/images/I/51J2ZU5tKjL._SL75_.jpg</URL>
        //                <Height Units="pixels">75</Height>
        //                <Width Units="pixels">75</Width>
        //            </SmallImage>
        //            <MediumImage>
        //            .......

        if (xmlDocNoXmlns != null)
        {
            XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
            if (itemsNode != null)
            {
                if (requestIsValid(itemsNode))
                {
                    //find current item asin and parentasin
                    XmlNode itemNode = itemsNode.SelectSingleNode("./Item");
                    if (itemNode != null)
                    {
                        XmlNode variationsNode = itemNode.SelectSingleNode("./Variations");
                        if (variationsNode != null)
                        {
                            //has variations

                            //build variation list
                            XmlNodeList variationsItemNodeList = variationsNode.SelectNodes("./Item");
                            if (variationsItemNodeList != null)
                            {
                                foreach (XmlNode variationItemNode in variationsItemNodeList)
                                {
                                    XmlNode eachAsinNode = variationItemNode.SelectSingleNode("./ASIN");
                                    XmlNode eachParentAsinNode = variationItemNode.SelectSingleNode("./ParentASIN");
                                    awsSearchResultItem eachItem = new awsSearchResultItem();
                                    eachItem.Asin = eachAsinNode.InnerText;
                                    eachItem.ParentAsin = eachParentAsinNode.InnerText;

                                    variationItemList.Add(eachItem);
                                }
                            }
                        }
                        else
                        {
                            //no variation
                            //only add current item

                            awsSearchResultItem singleItem = new awsSearchResultItem();

                            XmlNode curAsinNode = itemNode.SelectSingleNode("./ASIN");
                            singleItem.Asin = curAsinNode.InnerText;

                            //special:
                            //<Item>
                            //    <ASIN>B00162723O</ASIN>
                            //</Item>
                            XmlNode curParentAsinNode = itemNode.SelectSingleNode("./ParentASIN");
                            if (curParentAsinNode != null)
                            {
                                singleItem.ParentAsin = curParentAsinNode.InnerText;
                            }

                            variationItemList.Add(singleItem);
                        }
                    }
                }
            }
            else
            {
                //something wrong
                gLogger.Debug(String.Format("not found /ItemSearchResponse/Items for ASIN={0}", itemAsin));
            }
        }

        return variationItemList;
    }


    /*
     * [Function]
     * find variation item list for single asin
     * [Input]
     * single asin
     * eg:
     * B003F4TH6G
     * B0009IQZH0
     * B0000BX6RG
     * B001GJ3EJS
     * 
     * [Output]
     * variation item list
     * 
     * [Note]
     * 1. if not variation, then self is a single variation, will added into variation item list
     */
    public awsItemAttributes awsGetItemAttributes(string itemAsin)
    {
        //debug 
        //itemAsin = "B0000BX6RG";

        awsItemAttributes itemAttributes = new awsItemAttributes();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        reqDict["ResponseGroup"] = "ItemAttributes";

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        //special: no Feature list
        //<Item>
        //    <ASIN>B0000BX6RG</ASIN>
        //    <DetailPageURL>http://www.amazon.com/Meguiars-M4616-Gold-Teak-Oil/dp/B0000BX6RG%3FSubscriptionId%3DAKIAJQAUAH2R4HCG63LQ%26tag%3Dcrifancom-20%26linkCode%3Dxm2%26camp%3D2025%26creative%3D165953%26creativeASIN%3DB0000BX6RG</DetailPageURL>
        //    <ItemLinks>
        //        ......
        //    </ItemLinks>
        //    <ItemAttributes>
        //        <Binding>Automotive</Binding>
        //        <Brand>Meguiar's</Brand>
        //        <CatalogNumberList>
        //            <CatalogNumberListElement>290-M4616</CatalogNumberListElement>
        //            <CatalogNumberListElement>MEG-M4616</CatalogNumberListElement>
        //            <CatalogNumberListElement>M4616</CatalogNumberListElement>
        //            <CatalogNumberListElement>Website</CatalogNumberListElement>
        //        </CatalogNumberList>
        //        <EAN>0070382346164</EAN>
        //        <EANList>
        //            <EANListElement>0070382346164</EANListElement>
        //            <EANListElement>0070382800413</EANListElement>
        //        </EANList>
        //        <IsAutographed>0</IsAutographed>
        //        <IsMemorabilia>0</IsMemorabilia>
        //        <ItemDimensions>
        //            <Height Units="hundredths-inches">860</Height>
        //            <Length Units="hundredths-inches">190</Length>
        //            <Weight Units="hundredths-pounds">100</Weight>
        //            <Width Units="hundredths-inches">400</Width>
        //        </ItemDimensions>
        //        <Label>Meguiar's</Label>
        //        <ListPrice>
        //            <Amount>1549</Amount>
        //            <CurrencyCode>USD</CurrencyCode>
        //            <FormattedPrice>$15.49</FormattedPrice>
        //        </ListPrice>
        //        <Manufacturer>Meguiar's</Manufacturer>
        //        <ManufacturerPartsWarrantyDescription>Parts</ManufacturerPartsWarrantyDescription>
        //        <Model>M4616</Model>
        //        <MPN>M4616</MPN>
        //        <PackageDimensions>
        //            <Height Units="hundredths-inches">170</Height>
        //            <Length Units="hundredths-inches">840</Length>
        //            <Weight Units="hundredths-pounds">90</Weight>
        //            <Width Units="hundredths-inches">350</Width>
        //        </PackageDimensions>
        //        <PackageQuantity>1</PackageQuantity>
        //        <PartNumber>M4616</PartNumber>
        //        <ProductGroup>Automotive Parts and Accessories</ProductGroup>
        //        <ProductTypeName>AUTO_ACCESSORY</ProductTypeName>
        //        <Publisher>Meguiar's</Publisher>
        //        <Size>16 Ounce</Size>
        //        <SKU>290-M4616</SKU>
        //        <Studio>Meguiar's</Studio>
        //        <Title>Meguiar's M4616 Gold Teak Oil</Title>
        //        <UPC>070382800413</UPC>
        //        <UPCList>
        //            <UPCListElement>070382800413</UPCListElement>
        //            <UPCListElement>070382346164</UPCListElement>
        //        </UPCList>
        //    </ItemAttributes>
        //</Item>
        //</Items>

        XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
        if (requestIsValid(itemsNode))
        {
            XmlNode itemNode = itemsNode.SelectSingleNode("./Item");

            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
            itemAttributes.Asin = asinNode.InnerText;

            XmlNode parentAsinNode = itemNode.SelectSingleNode("./ParentASIN");
            if (parentAsinNode != null)
            {
                //special:
                //"B00162723O" no ParentASIN

                itemAttributes.ParentAsin = parentAsinNode.InnerText;
            }

            XmlNode itemAttributesNode = itemNode.SelectSingleNode("./ItemAttributes");

            //1.title
            XmlNode titleNode = itemAttributesNode.SelectSingleNode("./Title");
            itemAttributes.Title = titleNode.InnerText;

            //2.list price
            XmlNode listPriceNode = itemAttributesNode.SelectSingleNode("./ListPrice");
            if (listPriceNode != null)
            {
                itemAttributes.listPrice = new awsListPrice();

                XmlNode amountNode = listPriceNode.SelectSingleNode("./Amount");
                itemAttributes.listPrice.Amount = amountNode.InnerText; //"13999"

                XmlNode currencyCodeNode = listPriceNode.SelectSingleNode("./CurrencyCode");
                itemAttributes.listPrice.CurrencyCode = currencyCodeNode.InnerText; //"USD"

                XmlNode formattedPriceNode = listPriceNode.SelectSingleNode("./FormattedPrice");
                itemAttributes.listPrice.FormattedPrice = formattedPriceNode.InnerText; //"$139.99"
            }

            //3. feature list
            XmlNodeList featureNodeList = itemAttributesNode.SelectNodes("./Feature");
            if ((featureNodeList != null) && (featureNodeList.Count > 0))
            {
                itemAttributes.FeatureList = new List<string>();

                foreach (XmlNode featureNode in featureNodeList)
                {
                    itemAttributes.FeatureList.Add(featureNode.InnerText);
                }

                //"B0028AYQDC" has 7 features
                //"B00009W3G7"has 2 features
                //"B006YG683C" has 9 features
            }

            //4. item dimensions
            XmlNode itemDimensionsNode = itemAttributesNode.SelectSingleNode("./ItemDimensions");
            if (itemDimensionsNode != null)
            {
                itemAttributes.itemDimensions = new awsProductDimension();

                //special:
                //"B005F1Q5I0" no dimensions

                XmlNode lengthNode = itemDimensionsNode.SelectSingleNode("./Length");
                if (lengthNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (lengthNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.itemDimensions.LengthHundredthsInch = lengthNode.InnerText; //"1325"
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no item dimension length", itemAsin));
                }

                XmlNode widthNode = itemDimensionsNode.SelectSingleNode("./Width");
                if (widthNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (widthNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.itemDimensions.WidthHundredthsInch = widthNode.InnerText; //"1600"
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no item dimension width", itemAsin));
                }

                XmlNode heightNode = itemDimensionsNode.SelectSingleNode("./Height");
                if (heightNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (heightNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.itemDimensions.HeightHundredthsInch = heightNode.InnerText; //"1200"
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no item dimension height", itemAsin));
                }

                XmlNode weightNode = itemDimensionsNode.SelectSingleNode("./Weight");
                if (weightNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (weightNode.Attributes["Units"].Value == "hundredths-pounds")
                    {
                        itemAttributes.itemDimensions.WeightPound = weightNode.InnerText; //"0"
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no item dimension weight", itemAsin));
                }
            }


            //5. package dimensions
            XmlNode packageDimensionsNode = itemAttributesNode.SelectSingleNode("./PackageDimensions");
            if (packageDimensionsNode != null)
            {
                itemAttributes.packageDimensions = new awsProductDimension();

                XmlNode lengthNode = packageDimensionsNode.SelectSingleNode("./Length");
                if (lengthNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (lengthNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.packageDimensions.LengthHundredthsInch = lengthNode.InnerText;
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no package dimension length", itemAsin));
                }

                XmlNode widthNode = packageDimensionsNode.SelectSingleNode("./Width");
                if (widthNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (widthNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.packageDimensions.WidthHundredthsInch = widthNode.InnerText;
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no package dimension width", itemAsin));
                }

                XmlNode heightNode = packageDimensionsNode.SelectSingleNode("./Height");
                if (heightNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (heightNode.Attributes["Units"].Value == "hundredths-inches")
                    {
                        itemAttributes.packageDimensions.HeightHundredthsInch = heightNode.InnerText;
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no package dimension height", itemAsin));
                }

                XmlNode weightNode = packageDimensionsNode.SelectSingleNode("./Weight");
                if (weightNode != null)
                {
                    //makesure unit is expected: hundredths-inches
                    if (weightNode.Attributes["Units"].Value == "hundredths-pounds")
                    {
                        itemAttributes.packageDimensions.WeightPound = weightNode.InnerText;
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("{0} no package dimension weight", itemAsin));
                }

                //B003ZAFSHW
                //<ItemDimensions>
                //    <Height Units="hundredths-inches">3500</Height>
                //    <Length Units="hundredths-inches">1900</Length>
                //    <Width Units="hundredths-inches">2200</Width>
                //</ItemDimensions>
                //......
                //<PackageDimensions>
                //    <Height Units="hundredths-inches">1975</Height>
                //    <Length Units="hundredths-inches">3400</Length>
                //    <Weight Units="hundredths-pounds">8379</Weight>
                //    <Width Units="hundredths-inches">2250</Width>
                //</PackageDimensions>

            }

            //6. manufacturer
            XmlNode manufacturerNode = itemAttributesNode.SelectSingleNode("./Manufacturer");
            if (manufacturerNode != null)
            {
                itemAttributes.Manufacturer = manufacturerNode.InnerText; //"Frigidaire"
            }
        }

        return itemAttributes;
    }

    /*
     * [Function]
     * get item offers info
     * [Input]
     * single asin
     * eg:
     * B003F4TH6G
     * 
     * [Output]
     * offers response info
     * 
     * [Note]
     * 1. don not return Merchant even if pass Condition=All
     */
    public awsOffersInfo awsGetOffersInfo(string itemAsin, int itemPage = 1)
    {
        awsOffersInfo offersInfo = new awsOffersInfo();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/RG_Offers.html
        reqDict["ResponseGroup"] = "Offers";

        //https://affiliate-program.amazon.co.uk/gp/advertising/api/detail/api-changes.html?ie=UTF8&pf_rd_t=501&ref_=amb_link_83388313_2&pf_rd_m=A3P5ROKL5A1OLE&pf_rd_p=&pf_rd_s=assoc-center-1&pf_rd_r=&pf_rd_i=assoc-api-detail-2-v2
        //reqDict["MerchantId"] = "All";

        reqDict["Condition"] = "All";

        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/ItemSearch.html
        reqDict["ItemPage"] = itemPage.ToString();

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        //<Offers>
        //    <TotalOffers>2</TotalOffers>
        //    <TotalOfferPages>1</TotalOfferPages>
        //    <MoreOffersUrl>http://www.amazon.com/gp/offer-listing/B003F4TH6G%3FSubscriptionId%3DAKIAJQAUAH2R4HCG63LQ%26tag%3Dcrifancom-20%26linkCode%3Dxm2%26camp%3D2025%26creative%3D386001%26creativeASIN%3DB003F4TH6G</MoreOffersUrl>
        //    <Offer>
        //        <OfferAttributes>
        //            <Condition>New</Condition>
        //        </OfferAttributes>
        //        <OfferListing>
        //            <OfferListingId>ghnOgdC9i%2FJf93zUZK99kggmB%2FWJuV956JA07yVwWmSsR%2B0tOOePsNUGaIyPlczywBbni19SdCKVqsuQ6REyf60ItfvU9JG3RYikEuzEK2SGDyeLzYuOTUcqm5vP3zQazLjMgTS%2BmaXqmgnuvlLuIg%3D%3D</OfferListingId>
        //            <Price>
        //                <Amount>10999</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$109.99</FormattedPrice>
        //            </Price>
        //            <AmountSaved>
        //                <Amount>3000</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$30.00</FormattedPrice>
        //            </AmountSaved>
        //            <PercentageSaved>21</PercentageSaved>
        //            <Availability>Usually ships in 1-2 business days</Availability>
        //            <AvailabilityAttributes>
        //                <AvailabilityType>now</AvailabilityType>
        //                <MinimumHours>24</MinimumHours>
        //                <MaximumHours>48</MaximumHours>
        //            </AvailabilityAttributes>
        //            <IsEligibleForSuperSaverShipping>0</IsEligibleForSuperSaverShipping>
        //        </OfferListing>
        //    </Offer>
        //    <Offer>
        //        <OfferAttributes>
        //            <Condition>Used</Condition>
        //        </OfferAttributes>
        //        <OfferListing>
        //            <OfferListingId>nepEhXH5gqPluZ6nyFLB%2BH%2FxQyE%2F4fvTbqp0GlDIM7X%2F9A0u6WZMQVDasLTVToeUvFfuM2%2FbN2roxYvDJ2c%2FAGXcaqbB57uAfNEO%2FsqG%2Bo5WuqxhcG3iYZznpic2dh5aFFrv4s3cAUUxaHaMQOaTpg%3D%3D</OfferListingId>
        //            <Price>
        //                <Amount>10000</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$100.00</FormattedPrice>
        //            </Price>
        //            <AmountSaved>
        //                <Amount>3999</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$39.99</FormattedPrice>
        //            </AmountSaved>
        //            <PercentageSaved>29</PercentageSaved>
        //            <Availability>Usually ships in 1-2 business days</Availability>
        //            <AvailabilityAttributes>
        //                <AvailabilityType>now</AvailabilityType>
        //                <MinimumHours>24</MinimumHours>
        //                <MaximumHours>48</MaximumHours>
        //            </AvailabilityAttributes>
        //            <IsEligibleForSuperSaverShipping>0</IsEligibleForSuperSaverShipping>
        //        </OfferListing>
        //    </Offer>
        //</Offers>


        XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
        if (requestIsValid(itemsNode))
        {
            XmlNode itemNode = itemsNode.SelectSingleNode("./Item");

            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
            offersInfo.Asin = asinNode.InnerText;

            //special: no OfferSummary, no Offers
            //<Items>
            //    <Request>
            //        <IsValid>True</IsValid>
            //        <ItemLookupRequest>
            //            <Condition>All</Condition>
            //            <IdType>ASIN</IdType>
            //            <ItemId>B004FGMDOQ</ItemId>
            //            <ResponseGroup>Offers</ResponseGroup>
            //            <VariationPage>All</VariationPage>
            //        </ItemLookupRequest>
            //    </Request>
            //    <Item>
            //        <ASIN>B004FGMDOQ</ASIN>
            //    </Item>
            //</Items>

            XmlNode offerSummaryNode = itemNode.SelectSingleNode("./OfferSummary");
            if (offerSummaryNode != null)
            {
                //1. TotalNew
                XmlNode totalNewNode = offerSummaryNode.SelectSingleNode("./TotalNew");
                offersInfo.TotalNew = totalNewNode.InnerText; //"24"

                //2. TotalUsed
                XmlNode totalUsedNode = offerSummaryNode.SelectSingleNode("./TotalUsed");
                offersInfo.TotalUsed = totalUsedNode.InnerText; //"1"

                //3. TotalCollectible
                XmlNode totalCollectibleNode = offerSummaryNode.SelectSingleNode("./TotalCollectible");
                if (totalCollectibleNode != null)
                {
                    offersInfo.TotalCollectible = totalCollectibleNode.InnerText; //"0"
                }

                //4. TotalRefurbished
                XmlNode totalRefurbishedNode = offerSummaryNode.SelectSingleNode("./TotalRefurbished");
                if (totalRefurbishedNode != null)
                {
                    offersInfo.TotalRefurbished = totalRefurbishedNode.InnerText; //"0"
                }
            }
            else
            {
                gLogger.Debug("No OfferSummary for ItemLookupResponse of ASIN=" + itemAsin);
            }

            XmlNode offersNode = itemNode.SelectSingleNode("./Offers");
            if (offersNode != null)
            {
                //5. TotalOffers
                XmlNode totalOffersNode = offersNode.SelectSingleNode("./TotalOffers");
                offersInfo.TotalOffers = totalOffersNode.InnerText; //"1"

                //6. TotalOfferPages
                XmlNode totalOfferPagesNode = offersNode.SelectSingleNode("./TotalOfferPages");
                offersInfo.TotalOfferPages = totalOfferPagesNode.InnerText; //"1"
            }
            else
            {
                gLogger.Debug("No Offers for ItemLookupResponse of ASIN=" + itemAsin);
            }
        }

        return offersInfo;
    }


    /*
     * [Function]
     * get item offer full info
     * [Input]
     * single asin
     * eg:
     * B003F4TH6G
     * 
     * [Output]
     * offer full response info
     * 
     * [Note]
     */
    public awsOfferFullInfo awsGetOfferFullInfo(string itemAsin, int itemPage = 1)
    {
        awsOfferFullInfo offerFullInfo = new awsOfferFullInfo();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/RG_OfferFull.html
        reqDict["ResponseGroup"] = "OfferFull";

        //https://affiliate-program.amazon.co.uk/gp/advertising/api/detail/api-changes.html?ie=UTF8&pf_rd_t=501&ref_=amb_link_83388313_2&pf_rd_m=A3P5ROKL5A1OLE&pf_rd_p=&pf_rd_s=assoc-center-1&pf_rd_r=&pf_rd_i=assoc-api-detail-2-v2
        //reqDict["MerchantId"] = "All";

        reqDict["Condition"] = "All";

        reqDict["ItemPage"] = itemPage.ToString();

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        //<Offers>
        //    <TotalOffers>2</TotalOffers>
        //    <TotalOfferPages>1</TotalOfferPages>
        //    <MoreOffersUrl>http://www.amazon.com/gp/offer-listing/B003F4TH6G%3FSubscriptionId%3DAKIAJQAUAH2R4HCG63LQ%26tag%3Dcrifancom-20%26linkCode%3Dxm2%26camp%3D2025%26creative%3D386001%26creativeASIN%3DB003F4TH6G</MoreOffersUrl>
        //    <Offer>
        //        <Merchant>
        //            <Name>B&amp;G International</Name>
        //        </Merchant>
        //        <OfferAttributes>
        //            <Condition>New</Condition>
        //        </OfferAttributes>
        //        <OfferListing>
        //            <OfferListingId>5olWrpsQDrzXlfbNDsX0OYhUTAEFqR1BeoqsGzCm42qwupPs8OKTduttQUOZjnS%2FIy9LqtA4mSVnhzaEKp87lzTWTGB1WuZo%2FBBCo5l%2BdjoegXqhViwaYSU9%2FXFA45RCihHHtW6w3QbpKV54L%2FWITA%3D%3D</OfferListingId>
        //            <Price>
        //                <Amount>10999</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$109.99</FormattedPrice>
        //            </Price>
        //            <AmountSaved>
        //                <Amount>3000</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$30.00</FormattedPrice>
        //            </AmountSaved>
        //            <PercentageSaved>21</PercentageSaved>
        //            <Availability>Usually ships in 1-2 business days</Availability>
        //            <AvailabilityAttributes>
        //                <AvailabilityType>now</AvailabilityType>
        //                <MinimumHours>24</MinimumHours>
        //                <MaximumHours>48</MaximumHours>
        //            </AvailabilityAttributes>
        //            <IsEligibleForSuperSaverShipping>0</IsEligibleForSuperSaverShipping>
        //        </OfferListing>
        //    </Offer>
        //    <Offer>
        //        <Merchant>
        //            <Name>Dean.Rowbot</Name>
        //        </Merchant>
        //        <OfferAttributes>
        //            <Condition>Used</Condition>
        //        </OfferAttributes>
        //        <OfferListing>
        //            <OfferListingId>f33GbR9lXeie8Cg6au6aj%2F8ENH72QGXlxPo1pvL4HSB2Ik%2ByeHhGzQHRAL9%2FAFDhDWcKqLULu1nbQWAS2uJvUYjQ4OLkkAHW%2BWS7oUYzuvDawNCJ0JLA6d1C1eDSxFuUevjRa%2FSQjRdWhKC%2BPmD5LQ%3D%3D</OfferListingId>
        //            <Price>
        //                <Amount>10000</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$100.00</FormattedPrice>
        //            </Price>
        //            <AmountSaved>
        //                <Amount>3999</Amount>
        //                <CurrencyCode>USD</CurrencyCode>
        //                <FormattedPrice>$39.99</FormattedPrice>
        //            </AmountSaved>
        //            <PercentageSaved>29</PercentageSaved>
        //            <Availability>Usually ships in 1-2 business days</Availability>
        //            <AvailabilityAttributes>
        //                <AvailabilityType>now</AvailabilityType>
        //                <MinimumHours>24</MinimumHours>
        //                <MaximumHours>48</MaximumHours>
        //            </AvailabilityAttributes>
        //            <IsEligibleForSuperSaverShipping>0</IsEligibleForSuperSaverShipping>
        //        </OfferListing>
        //    </Offer>
        //</Offers>

        XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
        if (requestIsValid(itemsNode))
        {
            XmlNode itemNode = itemsNode.SelectSingleNode("./Item");

            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
            offerFullInfo.Asin = asinNode.InnerText;

            XmlNode offerSummaryNode = itemNode.SelectSingleNode("./OfferSummary");
            if (offerSummaryNode != null)
            {
                //1. TotalNew
                XmlNode totalNewNode = offerSummaryNode.SelectSingleNode("./TotalNew");
                offerFullInfo.TotalNew = totalNewNode.InnerText; //"24"

                //2. TotalUsed
                XmlNode totalUsedNode = offerSummaryNode.SelectSingleNode("./TotalUsed");
                offerFullInfo.TotalUsed = totalUsedNode.InnerText; //"1"

                //3. TotalCollectible
                XmlNode totalCollectibleNode = offerSummaryNode.SelectSingleNode("./TotalCollectible");
                if (totalCollectibleNode != null)
                {
                    offerFullInfo.TotalCollectible = totalCollectibleNode.InnerText; //"0"
                }

                //4. TotalRefurbished
                XmlNode totalRefurbishedNode = offerSummaryNode.SelectSingleNode("./TotalRefurbished");
                if (totalRefurbishedNode != null)
                {
                    offerFullInfo.TotalRefurbished = totalRefurbishedNode.InnerText; //"0"
                }
            }

            XmlNode offersNode = itemNode.SelectSingleNode("./Offers");
            if (offersNode != null)
            {
                //5. TotalOffers
                XmlNode totalOffersNode = offersNode.SelectSingleNode("./TotalOffers");
                offerFullInfo.TotalOffers = totalOffersNode.InnerText; //"1"

                //6. TotalOfferPages
                XmlNode totalOfferPagesNode = offersNode.SelectSingleNode("./TotalOffers");
                offerFullInfo.TotalOfferPages = totalOfferPagesNode.InnerText; //"1"

                //7. process each Offer
                XmlNodeList offerNodeList = offersNode.SelectNodes("./Offer");
                if ((offerNodeList != null) && (offerNodeList.Count > 0))
                {
                    offerFullInfo.offerList = new List<awsOffer>();

                    foreach (XmlNode offerNode in offerNodeList)
                    {
                        awsOffer singleOffer = new awsOffer();

                        //(1) Merchant
                        XmlNode merchantNode = offerNode.SelectSingleNode("./Merchant");
                        if (merchantNode != null)
                        {
                            //https://affiliate-program.amazon.co.uk/gp/advertising/api/detail/api-changes.html?ie=UTF8&pf_rd_t=501&ref_=amb_link_83388313_2&pf_rd_m=A3P5ROKL5A1OLE&pf_rd_p=&pf_rd_s=assoc-center-1&pf_rd_r=&pf_rd_i=assoc-api-detail-2-v2
                            //so now seems no MerchantId anymore
                            //XmlNode merchantIdNode = merchantNode.SelectSingleNode("./MerchantId");
                            //if (merchantIdNode != null)
                            //{
                            //    singleOffer.MerchantId = merchantIdNode.InnerText;
                            //}

                            XmlNode merchantNameNode = merchantNode.SelectSingleNode("./Name");
                            if (merchantNameNode != null)
                            {
                                singleOffer.MerchantName = merchantNameNode.InnerText; //"B&G International"
                            }

                            offerFullInfo.offerList.Add(singleOffer);
                        }
                    }
                }
                else
                {
                    gLogger.Debug(String.Format("not found Offer List for ASIN={0}", itemAsin));
                }
            }
            else
            {
                gLogger.Debug(String.Format("not found Offers for ASIN={0}", itemAsin));
            }
        }

        return offerFullInfo;
    }


    /*
     * [Function]
     * get item EditorialReview
     * [Input]
     * single asin
     * eg:
     * B003F4TH6G
     * 
     * [Output]
     * EditorialReview response
     * 
     * [Note]
     */
    public awsEditorialReview awsGetEditorialReview(string itemAsin)
    {
        awsEditorialReview editorialReview = new awsEditorialReview();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/RG_EditorialReview.html
        reqDict["ResponseGroup"] = "EditorialReview";

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
        if (requestIsValid(itemsNode))
        {
            XmlNode itemNode = itemsNode.SelectSingleNode("./Item");
            
            //<Item>
            //    <ASIN>B003F4TH6G</ASIN>
            //    <ParentASIN>B00B2R5QPO</ParentASIN>
            //    <EditorialReviews>
            //        <EditorialReview>
            //            <Source>Product Description</Source>
            //            <Content>&lt;!------- A+ Content Begins Here -------&gt; &lt;div class="aplus"&gt; &lt;!------- BRAND LOGO -------&gt; &lt;br&gt; &lt;img src="http://g-ec2.images-amazon.com/images/G/01/vince/almo/detail/FrigidaireLogo._SL600_.jpg" width="25%" ............................; &lt;!------- A+ Page Ends Here -------&gt;</Content>
            //            <IsLinkSuppressed>1</IsLinkSuppressed>
            //        </EditorialReview>
            //    </EditorialReviews>
            //</Item>

            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
            editorialReview.Asin = asinNode.InnerText;

            //special:
            //B003P9VZ0W
            //no EditorialReview:
            //<Item>
            //    <ASIN>B003P9VZ0W</ASIN>
            //</Item>

            XmlNode editorialReviewsNode = itemNode.SelectSingleNode("./EditorialReviews");
            if (editorialReviewsNode != null)
            {
                XmlNode editorialReviewNode = editorialReviewsNode.SelectSingleNode("./EditorialReview");
                if (editorialReviewNode != null)
                {
                    XmlNode sourceNode = editorialReviewNode.SelectSingleNode("./Source");
                    if (sourceNode != null)
                    {
                        editorialReview.Source = sourceNode.InnerText; //"Product Description"
                    }

                    XmlNode contentNode = editorialReviewNode.SelectSingleNode("./Content");
                    if (contentNode != null)
                    {
                        //html, contain many tag
                        editorialReview.Content = contentNode.InnerText;
                    }
                    else
                    {
                        gLogger.Debug(String.Format("not find EditorialReview/Content for ASIN={0}", itemAsin));
                    }
                }
            }
            else
            {
                gLogger.Debug(String.Format("not find EditorialReviews for ASIN={0}", itemAsin));
            }
        }


        return editorialReview;
    }


    /*
     * [Function]
     * get item Images
     * [Input]
     * single asin
     * eg:
     * B003F4TH6G
     * 
     * [Output]
     * Images response
     * 
     * [Note]
     */
    public awsImages awsGetImages(string itemAsin)
    {
        awsImages imagesInfo = new awsImages();

        IDictionary<string, string> reqDict = new Dictionary<string, String>();
        reqDict["Service"] = "AWSECommerceService";
        reqDict["Version"] = awsApiVersion;
        reqDict["Operation"] = "ItemLookup";
        reqDict["IdType"] = "ASIN";
        reqDict["ItemId"] = itemAsin;
        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/RG_Images.html
        reqDict["ResponseGroup"] = "Images";

        //http://docs.aws.amazon.com/AWSECommerceService/latest/DG/RG_Large.html
        //reqDict["ResponseGroup"] = "Images,Large";
        //reqDict["VariationPage"] = "All";

        String awsReqUrl = Sign(reqDict);
        XmlDocument xmlDocNoXmlns = awsReqUrlToXmlDoc_noXmlns(awsReqUrl);

        XmlNode itemsNode = xmlDocNoXmlns.SelectSingleNode("/ItemLookupResponse/Items");
        if (requestIsValid(itemsNode))
        {
            XmlNode itemNode = itemsNode.SelectSingleNode("./Item");
            
            XmlNode asinNode = itemNode.SelectSingleNode("./ASIN");
            imagesInfo.Asin = asinNode.InnerText;
            
            //<ImageSets>
            //    <ImageSet Category="primary">
            //        <SwatchImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL30_.jpg</URL>
            //            <Height Units="pixels">30</Height>
            //            <Width Units="pixels">23</Width>
            //        </SwatchImage>
            //        <SmallImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </SmallImage>
            //        <ThumbnailImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </ThumbnailImage>
            //        <TinyImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL110_.jpg</URL>
            //            <Height Units="pixels">110</Height>
            //            <Width Units="pixels">85</Width>
            //        </TinyImage>
            //        <MediumImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL160_.jpg</URL>
            //            <Height Units="pixels">160</Height>
            //            <Width Units="pixels">123</Width>
            //        </MediumImage>
            //        <LargeImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL.jpg</URL>
            //            <Height Units="pixels">500</Height>
            //            <Width Units="pixels">385</Width>
            //        </LargeImage>
            //    </ImageSet>
            //    <ImageSet Category="swatch">
            //        <SwatchImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL30_.jpg</URL>
            //            <Height Units="pixels">30</Height>
            //            <Width Units="pixels">23</Width>
            //        </SwatchImage>
            //        <SmallImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </SmallImage>
            //        <ThumbnailImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </ThumbnailImage>
            //        <TinyImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL110_.jpg</URL>
            //            <Height Units="pixels">110</Height>
            //            <Width Units="pixels">85</Width>
            //        </TinyImage>
            //        <MediumImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL._SL160_.jpg</URL>
            //            <Height Units="pixels">160</Height>
            //            <Width Units="pixels">123</Width>
            //        </MediumImage>
            //        <LargeImage>
            //            <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL.jpg</URL>
            //            <Height Units="pixels">500</Height>
            //            <Width Units="pixels">385</Width>
            //        </LargeImage>
            //    </ImageSet>
            //    <ImageSet Category="variant">
            //        <SwatchImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L._SL30_.jpg</URL>
            //            <Height Units="pixels">30</Height>
            //            <Width Units="pixels">23</Width>
            //        </SwatchImage>
            //        <SmallImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </SmallImage>
            //        <ThumbnailImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L._SL75_.jpg</URL>
            //            <Height Units="pixels">75</Height>
            //            <Width Units="pixels">58</Width>
            //        </ThumbnailImage>
            //        <TinyImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L._SL110_.jpg</URL>
            //            <Height Units="pixels">110</Height>
            //            <Width Units="pixels">85</Width>
            //        </TinyImage>
            //        <MediumImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L._SL160_.jpg</URL>
            //            <Height Units="pixels">160</Height>
            //            <Width Units="pixels">123</Width>
            //        </MediumImage>
            //        <LargeImage>
            //            <URL>http://ecx.images-amazon.com/images/I/31z%2B1G7nq1L.jpg</URL>
            //            <Height Units="pixels">500</Height>
            //            <Width Units="pixels">385</Width>
            //        </LargeImage>
            //    </ImageSet>
            //</ImageSets>

            XmlNode imageSetsNode = itemNode.SelectSingleNode("./ImageSets");
            if (imageSetsNode != null)
            {
                XmlNodeList largeImageList = imageSetsNode.SelectNodes(".//LargeImage");
                if ((largeImageList != null) && (largeImageList.Count > 0))
                {
                    imagesInfo.LargeImageList = new List<awsImageItem>();

                    //<LargeImage>
                    //    <URL>http://ecx.images-amazon.com/images/I/319p6SN2ZwL.jpg</URL>
                    //    <Height Units="pixels">500</Height>
                    //    <Width Units="pixels">385</Width>
                    //</LargeImage>
                    foreach(XmlNode largeImageNode in largeImageList)
                    {
                        awsImageItem singleImageItem = new awsImageItem();

                        XmlNode urlNode = largeImageNode.SelectSingleNode("./URL");
                        XmlNode heightNode = largeImageNode.SelectSingleNode("./Height");
                        XmlNode widthNode = largeImageNode.SelectSingleNode("./Width");

                        //note, here maybe the URL is duplcated
                        singleImageItem.Url = urlNode.InnerText;
                        singleImageItem.HeightPixel = heightNode.InnerText;
                        singleImageItem.WidthPixel = widthNode.InnerText;

                        imagesInfo.LargeImageList.Add(singleImageItem);
                    }
                }
            }
            else
            {
                //special: no Images
                //<Items>
                //    <Request>
                //        <IsValid>True</IsValid>
                //        <ItemLookupRequest>
                //            <IdType>ASIN</IdType>
                //            <ItemId>B0007S5N8O</ItemId>
                //            <ResponseGroup>Images</ResponseGroup>
                //            <VariationPage>All</VariationPage>
                //        </ItemLookupRequest>
                //    </Request>
                //    <Item>
                //        <ASIN>B0007S5N8O</ASIN>
                //    </Item>
                //</Items>

                gLogger.Debug(String.Format("not find ImageSets for ASIN={0}", itemAsin));
            }
        }
        
        return imagesInfo;
    }    
    

    /********************************* AWS API *******************************/
}

