package main

func main() {
	var (
		v = newSettings()
		l = newLogger(v)
		g = newGracefulContext(l)
		a = newApp(g, l, v)
	)

	go a.Server(g)
	go a.Worker(g)

	a.Wait()
}
