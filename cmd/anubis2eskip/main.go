package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/skipper/eskip"
)

type config struct {
	backend     string
	policy      string
	denyFilters string
}

func main() {
	config := &config{
		backend:     withDefault(os.Getenv("BACKEND"), "https://example.com"),
		policy:      withDefault(os.Getenv("POLICY"), "./testdata/botPolicies.json"),
		denyFilters: withDefault(os.Getenv("DENY_FILTERS"), `status(403) -> inlineContent("Forbidden")`),
	}

	var policies struct {
		Bots []struct {
			Name            string
			UserAgent       string `json:"user_agent_regex"`
			Action          string
			RemoteAddresses []any  `json:"remote_addresses"`
			PathRegex       string `json:"path_regex"`
		}
	}
	err := json.Unmarshal(must(os.ReadFile(config.policy)), &policies)
	if err != nil {
		panic(err)
	}

	denyFilters := eskip.MustParseFilters(config.denyFilters)

	var routes []*eskip.Route
	for _, bot := range policies.Bots {
		if bot.Action == "CHALLENGE" {
			// define challenge routes in skipper config
			continue
		}

		route := &eskip.Route{
			Id: strings.ReplaceAll(fmt.Sprintf("%s_%s", bot.Name, bot.Action), "-", "_"),
		}

		if len(bot.RemoteAddresses) > 0 {
			route.Predicates = append(route.Predicates, &eskip.Predicate{
				Name: "SourceFromLast", Args: bot.RemoteAddresses,
			})
		}

		if bot.UserAgent != "" {
			route.Predicates = append(route.Predicates, &eskip.Predicate{
				Name: "HeaderRegexp", Args: []any{"User-Agent", bot.UserAgent},
			})
		}

		if bot.PathRegex != "" {
			route.Predicates = append(route.Predicates, &eskip.Predicate{
				Name: "PathRegexp", Args: []any{bot.PathRegex},
			})
		}

		switch bot.Action {
		case "ALLOW":
			route.Backend = config.backend
		case "DENY":
			route.Filters = denyFilters
			route.BackendType = eskip.ShuntBackend
		default:
			panic(fmt.Sprintf("unsupported action type: %q", bot.Action))
		}
		routes = append(routes, route)
	}
	fmt.Println("// This file is generated from [Anubis](https://github.com/TecharoHQ/anubis) botPolicies.json")
	fmt.Println("//")
	fmt.Printf("//     (cd ./cmd/anubis2eskip/ && BACKEND=%q POLICY=%q go run . > doc/botPolicies.eskip)\n", config.backend, config.policy)
	fmt.Println("//")
	fmt.Println(eskip.Print(eskip.PrettyPrintInfo{Pretty: true}, routes...))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func withDefault[T comparable](val, def T) T {
	var zero T
	if val == zero {
		return def
	}
	return val
}
