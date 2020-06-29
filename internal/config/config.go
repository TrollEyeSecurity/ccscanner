package config

import (
	"encoding/json"
	"fmt"
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
