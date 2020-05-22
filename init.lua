--
-- Created by IntelliJ IDEA.
-- User: johnsun
-- Date: 2020/5/21
-- Time: 3:09 PM
-- To change this template use File | Settings | File Templates.
--

print("Hello APIs.")

local uri = ngx.var.uri

print(uri)

return ngx.exit(ngx.HTTP_UNAUTHORIZED)