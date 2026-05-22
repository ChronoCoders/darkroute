package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Tier string `json:"tier"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

func NewJWTManager(secret string) *JWTManager {
	return &JWTManager{secret: []byte(secret), ttl: 8 * time.Hour}
}

func (m *JWTManager) GenerateToken(sub, role, tier string) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:  sub,
		Role: role,
		Tier: tier,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

func (m *JWTManager) ValidateToken(tokenStr string) (*Claims, error) {
	// Spec §4 / §7.1 mandates HS256. Accepting the broader HMAC family
	// would widen the verifier surface to HS384/HS512 (same secret bytes,
	// different hash); reject anything but HS256 explicitly. Likewise,
	// require `exp` so a token crafted with the secret cannot live forever.
	parsed, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("invalid signing method")
			}
			return m.secret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
