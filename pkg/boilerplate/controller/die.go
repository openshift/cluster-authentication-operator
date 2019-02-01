package controller

type die string

func crash(i interface{}) {
	mustDie, ok := i.(die)
	if ok {
		panic(string(mustDie))
	}
}
