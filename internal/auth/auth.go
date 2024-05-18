package auth

const (
	nameKey = "name"
)

type Info struct {
	Attrs map[string]string `json:"attrs"`
}

func (i *Info) GetAttr(key string) (string, bool) {
	a, ok := i.Attrs[key]
	return a, ok
}

func (i *Info) GetPeerName() (string, bool) {
	return i.GetAttr(nameKey)
}
