package waf

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func BoolToInt(v bool) int {
	if v {
		return 1
	} else {
		return 0
	}
}
func IsIPAddress(ip string) bool {
	address := net.ParseIP(ip)
	if address == nil {

		return false
	} else {
		return true
	}
}
func ResourceApp() *schema.Resource {
	return &schema.Resource{
		Create: resourceWAFAppCreate,
		Read:   resourceWAFAppRead,
		Update: resourceWAFAppUpdate,
		Delete: resourceWAFAppDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"app_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"domain_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"extra_domains": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"app_service": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeInt,
				},
			},
			"origin_server_ip": {
				Type:     schema.TypeString,
				Required: true,
			},
			"origin_server_service": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "HTTPS",
			},
			"origin_server_port": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  443,
			},
			"cdn": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"continent_cdn": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"continent": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"block": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"template": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
			"cname": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"ep_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}
func getMapIntVal(v interface{}) map[string]int {
	if v == nil {
		return map[string]int{}
	}
	m := make(map[string]int)
	for k, val := range v.(map[string]interface{}) {
		m[k] = val.(int)
	}
	return m

}

func resourceWAFAppCreate(d *schema.ResourceData, m interface{}) error {
	c := m.(*WAFClient).CloudClient

	if c == nil {
		return fmt.Errorf("WAF client did not initialize successfully!")
	}

	//Get Params from d
	appName := d.Get("app_name").(string)
	domain := d.Get("domain_name").(string)

	extraDomains := d.Get("extra_domains").([]interface{})

	server := d.Get("origin_server_ip").(string)
	service := d.Get("origin_server_service").(string)
	service = strings.ToUpper(service)
	cdn := d.Get("cdn").(bool)
	continent_cdn := d.Get("continent_cdn").(bool)
	block := d.Get("block").(bool)
	template := d.Get("template").(string)

	template = strings.TrimSpace(template)
	appService := getMapIntVal(d.Get("app_service"))

	var templateId string
	var serverList []interface{} = nil
	var region map[string]interface{}
	var serverAddr string
	templateEnable := 0

	var testStatus map[string]interface{}

	custom := CustomPort{Http: appService["http"], Https: appService["https"]}

	var extra []string
	if extraDomains != nil {
		length := len(extraDomains)
		extra = make([]string, length)
		for i, e := range extraDomains {
			extra[i] = e.(string)
		}

	}

	if template != "" {
		tpl := Template{TemplateName: template}
		tClient := NewTemplateClient(c, &tpl)
		tClient.Send()
		retTpl, err := tClient.ReadData()
		if err != nil {
			return err
		}
		tplMap := retTpl.(map[string]interface{})
		templateId = tplMap["template_id"].(string)
		templateEnable = 1
	}
	serverAddr = server

	if !IsIPAddress(server) {
		dns := DnsLookup{Domain: server}
		dnsClient := NewDnsLookupClient(c, &dns)
		dnsClient.Send()
		readTmp, err := dnsClient.ReadData()
		if err != nil {
			return err
		}
		serverList = readTmp.([]interface{})
	}
	if c.Init {
		OutPut("client init is inited!")
	}

	if serverList != nil {
		flag := false
		for _, e := range serverList {
			serverTest := ServerTest{BackendIP: e.(string), BackendType: service, Domain: domain}
			stestClient := NewServerTestClient(c, &serverTest)
			stestClient.Send()
			testRead, err := stestClient.ReadData()

			if err == nil {
				testStatus = testRead.(map[string]interface{})
				flag = true
				ipregion := &IPRegion{Domain: domain, EpIP: e.(string), ExtraDomain: extra, CustomPort: custom}

				ipRegionClient := NewIPRegionClient(c, ipregion)
				ipRegionClient.Send()

				iregion, err := ipRegionClient.ReadData() // get_ip_region
				if err != nil {
					return err
				}
				region = iregion.(map[string]interface{})
				break
			}
		}
		if !flag {
			return fmt.Errorf("Couldn't find active server!")
		}
	} else {
		serverTest := ServerTest{BackendIP: serverAddr, BackendType: service, Domain: domain}
		stestClient := NewServerTestClient(c, &serverTest)
		stestClient.Send()
		testRead, err := stestClient.ReadData()
		if err != nil {
			return fmt.Errorf("WAF test server failed!" + err.Error())
		}

		testStatus = testRead.(map[string]interface{})

		ipregion := &IPRegion{Domain: domain, EpIP: serverAddr, ExtraDomain: extra, CustomPort: custom}

		ipRegionClient := NewIPRegionClient(c, ipregion)
		ipRegionClient.Send()

		iregion, err := ipRegionClient.ReadData() // get_ip_region
		if err != nil {
			return err
		}
		region = iregion.(map[string]interface{})
	}

	appQuery := &AppQuery{AppName: appName}
	queryClient := NewAppQueryClient(c, appQuery)
	queryClient.Send()
	appQ, errr := queryClient.ReadData()
	if errr != nil {
		return errr
	}
	var apiService [2]string
	var i int = 0
	var blockMode = BoolToInt(block)
	var cdnStatus = BoolToInt(cdn)
	var is_globa_cdn = BoolToInt(cdn && !continent_cdn)

	if _, ok := appService["http"]; ok {
		apiService[i] = "http"
		i += 1
	}
	if _, ok := appService["https"]; ok {
		apiService[i] = "https"
	}
	if appQ == nil {
		appCreate := &AppCreate{AppName: appName,
			DomainName:     domain,
			ExtraDomains:   extra,
			BlockMode:      blockMode,
			ServerAddress:  serverAddr,
			CustomPort:     custom,
			Service:        apiService, //list type
			Availability:   testStatus["head_availability"].(float64),
			StatusCode:     testStatus["head_status_code"].(float64),
			CDNStatus:      cdnStatus,
			IsGlobaCdn:     is_globa_cdn,
			TemplateEnable: templateEnable,
			TemplateId:     templateId,
			ServerType:     strings.ToLower(service), // origin_server_service
		}

		if !cdn {
			appCreate.ServerCountry, _ = region["location"].(string)
			cluster := region["cluster"].(map[string]interface{})
			appCreate.Region = cluster["single"].(string)
		}
		if cdn && is_globa_cdn == 0 {
			cluster := region["cluster"].(map[string]interface{})
			appCreate.Continent = cluster["continent"].(string)
			log.Printf("Continent CDN: %s", appCreate.Continent)
		} else {
			appCreate.Continent = ""
		}
		platformList := region["region"].([]interface{})
		if len(platformList) > 0 {
			appCreate.Platform = platformList[0].(string)
		} else {
			appCreate.Platform = "AWS"
		}
		app := NewAppCreateClient(c, appCreate)
		app.Send()
		createData, errr := app.ReadData()
		if errr != nil {
			return errr
		}
		retData, ok := createData.([]interface{})
		if !ok {
			OutPut("WAF client create app failed!")
			return fmt.Errorf("WAF client create app failed!")
		}
		var cnameList []string
		for _, elem := range retData {
			eleMap := elem.(map[string]interface{})

			cname := eleMap["dns"].(string)
			cnameList = append(cnameList, cname)

		}
		locJSON, _ := json.Marshal(cnameList)

		d.SetId(appName)
		d.Set("cname", string(locJSON))
		d.Set("continent", appCreate.Continent)

		ret := resourceWAFAppRead(d, m)
		if ret != nil {
			return ret
		}
		return nil
	} else {
		return fmt.Errorf(appName + " exists")
	}
}

func resourceWAFAppUpdate(d *schema.ResourceData, m interface{}) error {
	//not allowed update app config

	return resourceWAFAppRead(d, m)
}

func resourceWAFAppDelete(d *schema.ResourceData, m interface{}) error {

	c := m.(*WAFClient).CloudClient

	if c == nil {
		return fmt.Errorf("WAF client did not initialize successfully!")
	}

	//Call process by sdk
	appName := d.Id()
	appQuery := &AppQuery{AppName: appName}
	queryClient := NewAppQueryClient(c, appQuery)
	queryClient.Send()
	qApp, err := queryClient.ReadData()

	if qApp == nil {
		return fmt.Errorf("Couldn't find the right app name!:" + appName)
	}
	appMap := qApp.(map[string]interface{})
	ep_id := appMap["ep_id"].(string)

	delApp := AppDel{EPId: ep_id}
	if ep_id == "" {
		return fmt.Errorf("Empty ep id!")
	}
	delAppClient := NewAppDelClient(c, &delApp)
	delAppClient.Send()
	_, err = delAppClient.ReadData()
	if err == nil {
		d.SetId("")
		return nil
	} else {
		return err
	}

}

func resourceWAFAppRead(d *schema.ResourceData, m interface{}) error {
	appName := d.Id()

	c := m.(*WAFClient).CloudClient
	if c == nil {
		return fmt.Errorf("WAF client did not initialize successfully!")
	}

	appQuery := &AppQuery{AppName: appName}
	queryClient := NewAppQueryClient(c, appQuery)
	queryClient.Send()
	qApp, err := queryClient.ReadData()

	if qApp == nil {
		log.Printf("[WARN] resource (%s) not found, removing from state", d.Id())
		return err
	}
	app := qApp.(map[string]interface{})
	d.Set("ep_id", app["ep_id"].(string))
	return nil
}
