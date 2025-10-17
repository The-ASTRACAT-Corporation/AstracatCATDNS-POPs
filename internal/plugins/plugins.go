package plugins

import (
	"log"

	"github.com/miekg/dns"
)

// PluginContext holds context for a plugin's execution.
type PluginContext struct {
	ResponseWriter dns.ResponseWriter
	RequestHandled bool
	data           map[string]interface{}
}

// NewPluginContext creates a new PluginContext.
func NewPluginContext() *PluginContext {
	return &PluginContext{
		data: make(map[string]interface{}),
	}
}

// Set stores a value in the context.
func (c *PluginContext) Set(key string, value interface{}) {
	c.data[key] = value
}

// Get retrieves a value from the context.
func (c *PluginContext) Get(key string) (interface{}, bool) {
	val, ok := c.data[key]
	return val, ok
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
		if ctx.RequestHandled {
			return
		}
	}
}

// ResponsePlugin is an interface for plugins that want to handle responses.
type ResponsePlugin interface {
	Response(key string, response *dns.Msg, err error)
}

// ExecuteResponsePlugins runs plugins that implement the ResponsePlugin interface.
func (pm *PluginManager) ExecuteResponsePlugins(key string, response *dns.Msg, err error) {
	for _, p := range pm.plugins {
		if rp, ok := p.(ResponsePlugin); ok {
			rp.Response(key, response, err)
		}
	}
}