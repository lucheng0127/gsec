package handler

import (
	"net/http"

	"github.com/lucheng0127/gsec/api/internal/logic"
	"github.com/lucheng0127/gsec/api/internal/svc"
	"github.com/lucheng0127/gsec/api/internal/types"
	"github.com/zeromicro/go-zero/rest/httpx"
)

func ipsecHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.IpsecRequest
		if err := httpx.Parse(r, &req); err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
			return
		}

		l := logic.NewIpsecLogic(r.Context(), svcCtx)
		resp, err := l.Ipsec(&req)
		if err != nil {
			httpx.ErrorCtx(r.Context(), w, err)
		} else {
			httpx.OkJsonCtx(r.Context(), w, resp)
		}
	}
}
