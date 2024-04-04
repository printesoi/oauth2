package generates_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/printesoi/oauth2/v4"
	"github.com/printesoi/oauth2/v4/generates"
	"github.com/printesoi/oauth2/v4/models"

	. "github.com/smartystreets/goconvey/convey"
)

func TestJWTAccess(t *testing.T) {
	Convey("Test JWT Access Generate", t, func() {
		data := &oauth2.GenerateBasic{
			Client: &models.Client{
				ID:     "123456",
				Secret: "123456",
			},
			UserID: "000000",
			TokenInfo: &models.Token{
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 120,
			},
		}

		gen := generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512)
		access, refresh, err := gen.Token(context.Background(), data, true)
		So(err, ShouldBeNil)
		So(access, ShouldNotBeEmpty)
		So(refresh, ShouldNotBeEmpty)

		token, err := jwt.ParseWithClaims(access, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("parse error")
			}
			return []byte("00000000"), nil
		})
		So(err, ShouldBeNil)

		claims, ok := token.Claims.(*generates.JWTAccessClaims)
		So(ok, ShouldBeTrue)
		So(token.Valid, ShouldBeTrue)
		So(claims.Audience, ShouldEqual, jwt.ClaimStrings{"123456"})
		So(claims.Subject, ShouldEqual, "000000")
		So(claims.Rand, ShouldBeEmpty)
	})
}

func TestJWTAccessRand(t *testing.T) {
	Convey("Test JWT Access Generate Random", t, func() {
		data := &oauth2.GenerateBasic{
			Client: &models.Client{
				ID:     "123456",
				Secret: "123456",
			},
			UserID: "",
			TokenInfo: &models.Token{
				AccessCreateAt:  time.Now(),
				AccessExpiresIn: time.Second * 120,
			},
		}

		gen := generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512)
		gen.Randomizer = generates.RandomizerFunc(func() string {
			return "12345"
		})
		access, refresh, err := gen.Token(context.Background(), data, true)
		So(err, ShouldBeNil)
		So(access, ShouldNotBeEmpty)
		So(refresh, ShouldNotBeEmpty)

		token, err := jwt.ParseWithClaims(access, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("parse error")
			}
			return []byte("00000000"), nil
		})
		So(err, ShouldBeNil)

		claims, ok := token.Claims.(*generates.JWTAccessClaims)
		So(ok, ShouldBeTrue)
		So(token.Valid, ShouldBeTrue)
		So(claims.Audience, ShouldEqual, jwt.ClaimStrings{"123456"})
		So(claims.Subject, ShouldBeEmpty)
		So(claims.Rand, ShouldEqual, "12345")
	})
}
