package plugins

import (
	"log"

	"github.com/miekg/dns"
)

// PluginContext holds context for a plugin's execution.
type PluginContext struct {
	ResponseWriter dns.ResponseWriter
	Stop           bool
}

// Plugin is the interface that all plugins must implement.
type Plugin interface {
	Name() string
	Execute(ctx *PluginContext, msg *dns.Msg) error
}

// PluginManager manages the lifecycle of plugins.
type PluginManager struct {
	plugins []Plugin
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make([]Plugin, 0),
	}
}

// Register adds a new plugin to the manager.
func (pm *PluginManager) Register(p Plugin) {
	log.Printf("Registering plugin: %s", p.Name())
	pm.plugins = append(pm.plugins, p)
}

// ExecutePlugins runs all registered plugins.
func (pm *PluginManager) ExecutePlugins(ctx *PluginContext, msg *dns.Msg) {
	for _, p := range pm.plugins {
		if err := p.Execute(ctx, msg); err != nil {
			log.Printf("Error executing plugin %s: %v", p.Name(), err)
		}
		if ctx.Stop {
			break
		}
	}
}