package main

func main() {
	var (
		v = newSettings()
		l = newLogger(v)
		a = newApp(l, v)
		g = newGracefulContext(l)
	)

	go a.Server(g)
	go a.Worker(g)

	a.Wait(g)
}
