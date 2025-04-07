package subdomain

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetInterfaceByDstIP(t *testing.T) {
	ifaceName, localIP, localMAC, gatewayMAC, err := getLocalRouteInfo("1.1.1.1")
	assert.NoError(t, err)
	assert.NotNil(t, localIP)
	assert.NotNil(t, localMAC)
	assert.NotNil(t, gatewayMAC)
	fmt.Println("网卡名:", ifaceName)
	fmt.Println("本地IP:", localIP)
	fmt.Println("本地MAC:", localMAC)
	fmt.Println("目标MAC（可能为空）:", gatewayMAC)
}
