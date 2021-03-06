package galf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/afex/hystrix-go/hystrix"
)

var hystrixConfigs map[string]*HystrixConfig
var hystrixMutex *sync.RWMutex

func init() {
	hystrixConfigs = make(map[string]*HystrixConfig)
	hystrixMutex = &sync.RWMutex{}
}

type HystrixConfig struct {
	Name       string
	configName string
}

func NewHystrixConfig(configName string) *HystrixConfig {
	return &HystrixConfig{
		Name:       formatHystrixConfigName(configName),
		configName: configName,
	}
}

func (hc *HystrixConfig) valid() error {
	hystrixMutex.RLock()
	defer hystrixMutex.RUnlock()

	_, exists := hystrixConfigs[hc.Name]
	if !exists {
		msg := fmt.Sprintf("Hystrix config name not found: %s", hc.configName)
		return errors.New(msg)
	}

	return nil
}

// ConfigureCommand applies settings for a circuit
func HystrixConfigureCommand(configName string, config hystrix.CommandConfig) {
	hystrixMutex.Lock()
	defer hystrixMutex.Unlock()

	hc := NewHystrixConfig(configName)
	hystrix.ConfigureCommand(hc.Name, config)
	hystrixConfigs[hc.Name] = hc
}

func formatHystrixConfigName(name string) string {
	return fmt.Sprintf("%s_galf", name)
}
