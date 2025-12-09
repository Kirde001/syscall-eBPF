.PHONY: install

install:
	# service
	install -d $(DESTDIR)/usr/sbin/
	install -m 0755 service/syscall-inspector.py $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/lib/systemd/system/
	install -m 0644 service/syscall-inspector.service $(DESTDIR)/usr/lib/systemd/system/
	
	# config defaults
	install -d $(DESTDIR)/etc/syscall-inspector/
	install -m 0644 service/config.conf $(DESTDIR)/etc/syscall-inspector/config.conf

	# ui & backend
	install -d $(DESTDIR)/usr/share/alterator/ui/syscall-inspector/
	install -m 0644 alterator/ui/* $(DESTDIR)/usr/share/alterator/ui/syscall-inspector/
	
	install -d $(DESTDIR)/usr/lib/alterator/backend3/
	install -m 0755 alterator/backend/syscall-inspector-backend $(DESTDIR)/usr/lib/alterator/backend3/syscall-inspector

	# desktop files
	install -d $(DESTDIR)/usr/share/alterator/applications/
	install -m 0644 alterator/syscall-inspector.desktop $(DESTDIR)/usr/share/alterator/applications/
	install -d $(DESTDIR)/usr/share/applications/
	install -m 0644 alterator/syscall-inspector-launcher.desktop $(DESTDIR)/usr/share/applications/
