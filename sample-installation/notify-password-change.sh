curl -i --user ad-pwd-sync:T0pS3cr3t! \
-H "Accept: application/json" \
-H "Content-Type: application/json" \
-X POST http://localhost:8080/midpoint/ws/rest/notifyChange \
--data-binary @notify-password-change.json
