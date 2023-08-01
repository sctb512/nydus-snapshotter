package auth

import (
	"github.com/pkg/errors"
	"k8s.io/utils/lru"
)

type Cache struct {
	keyRing *KeyRing
	cache   *lru.Cache
}

func NewCache() *Cache {
	return &Cache{
		keyRing: NewKeyRing(),
		cache:   lru.New(30),
	}
}

func (c *Cache) UpdateAuth(imageHost, auth string) error {
	key, err := c.keyRing.Add(imageHost, auth)
	if err != nil {
		return err
	}
	data, err := c.keyRing.GetData(key)
	if err != nil {
		return err
	}
	c.cache.Add(imageHost, data)
	return nil
}

func (c *Cache) GetAuth(imageHost string) (string, error) {
	if auth, ok := c.cache.Get(imageHost); ok {
		return auth.(string), nil
	}

	data, err := c.keyRing.Search(imageHost)
	if err != nil {
		return "", errors.Wrap(err, "search key error")

	}
	c.cache.Add(imageHost, data)

	return data, err
}
