package config

import (
	"encoding/json"
	"fmt"
	"github.com/TrollEyeSecurity/ccscanner/internal/database"
	"io/ioutil"
	"os"
)

func LoadConfiguration(file string) Config {
	var config Config
	if file != "" {
		configFile, err := os.Open(file)
		if err != nil {
			fmt.Println(err.Error())
		}
		if configFile != nil {
			jsonParser := json.NewDecoder(configFile)
			jsonParser.Decode(&config)
			configFile.Close()
		}
	}
	return config
}

func LoadDastConfiguration(file *string, rootUrl *string) *database.DastConfig {
	var config database.DastConfig
	if *file != "" {
		configFile, err := ioutil.ReadFile(*file)
		if err != nil {
			fmt.Println(err.Error())
		}
		if configFile != nil {
			config.WebappZapContext = string(configFile)
			config.WebappRooturl = *rootUrl
		}
	}
	return &config
}
