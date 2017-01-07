#
# Copyright 2015 VMware, Inc
#

SRCROOT := .
MAKEROOT=$(SRCROOT)/support/make
include $(MAKEROOT)/makedefs.mk

PACKAGES=\
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMEVENT_CLIENT_DEVEL_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_DEVEL_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_DEVEL_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_DEVEL_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_PYTHON_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_DEVEL_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMSTS_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(CFG_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(LW_SERVER_RPM) \
    $(LIGHTWAVE_STAGE_DIR)/x86_64/$(LW_CLIENTS_RPM)

all: $(LIGHTWAVE_STAGE_DIR) $(PACKAGES)

container: $(DOCKER_IMAGE)

$(DOCKER_IMAGE) : $(PACKAGES)
	$(CP) -f $(DOCKER_SRCROOT)/Dockerfile $(LIGHTWAVE_STAGE_DIR)/Dockerfile
	$(CP) -f $(DOCKER_SRCROOT)/lightwave-init $(LIGHTWAVE_STAGE_DIR)/lightwave-init
	$(CP) -f $(DOCKER_SRCROOT)/configure-lightwave-server.service $(LIGHTWAVE_STAGE_DIR)/configure-lightwave-server.service
	$(CP) -f $(DOCKER_SRCROOT)/configure-identity-server.service $(LIGHTWAVE_STAGE_DIR)/configure-identity-server.service
	$(DOCKER_BUILDER) $(LIGHTWAVE_STAGE_DIR) $@

container-published : container-published-prepare
	docker build -t $(DOCKER_IMAGE_TAG) --no-cache $(LIGHTWAVE_STAGE_DIR)/docker-published && \
	docker save $(DOCKER_IMAGE_TAG) > $(DOCKER_IMAGE) && \
	docker rmi $(DOCKER_IMAGE_TAG)

container-published-prepare: $(LIGHTWAVE_STAGE_DIR)
	$(MKDIR) -p $(LIGHTWAVE_STAGE_DIR)/docker-published && \
	$(CP) -f $(DOCKER_SRCROOT)/Dockerfile $(LIGHTWAVE_STAGE_DIR)/docker-published/Dockerfile && \
	$(CP) -f $(DOCKER_SRCROOT)/configure-lightwave-server.service $(LIGHTWAVE_STAGE_DIR)/docker-published/configure-lightwave-server.service && \
	$(CP) -f $(DOCKER_SRCROOT)/configure-identity-server.service $(LIGHTWAVE_STAGE_DIR)/docker-published/configure-identity-server.service && \
	systemctl start docker

client-container: $(DOCKER_CLIENT_IMAGE)

$(DOCKER_CLIENT_IMAGE) : $(PACKAGES)
	$(CP) -f $(DOCKER_SRCROOT)/Dockerfile.client $(LIGHTWAVE_STAGE_DIR)/Dockerfile
	$(CP) -f $(DOCKER_SRCROOT)/configure-lightwave-client.service $(LIGHTWAVE_STAGE_DIR)/configure-lightwave-client.service
	$(DOCKER_CLIENT_BUILDER) $(LIGHTWAVE_STAGE_DIR) $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(LW_SERVER_RPM): $(LW_SERVER_PKGDIR)/$(LW_SERVER_RPM)
	$(CP) -f $< $@

$(LW_SERVER_PKGDIR)/$(LW_SERVER_RPM):
	@cd $(SRCROOT)/lw-server && make

lw-build-clean:
	$(RMDIR) $(LW_BUILD_SRCROOT)

lw-server-clean:
	@cd $(SRCROOT)/lw-server && make clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR) ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR) && $(RM) -f $(LW_SERVER_RPM); \
	fi

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(LW_CLIENTS_RPM): $(LW_CLIENTS_PKGDIR)/$(LW_CLIENTS_RPM)
	$(CP) -f $< $@

$(LW_CLIENTS_PKGDIR)/$(LW_CLIENTS_RPM):
	@cd $(SRCROOT)/lw-clients && make

lw-clients-clean:
	@cd $(SRCROOT)/lw-clients && make clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR) ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR) && $(RM) -f $(LW_CLIENTS_RPM); \
	fi

vmevent-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMEVENT_CLIENT_DEVEL_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMEVENT_CLIENT_DEVEL_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMEVENT_CLIENT_DEVEL_RPM): $(VMEVENT_PKGDIR)/$(VMEVENT_CLIENT_DEVEL_RPM)
	$(CP) -f $< $@

$(VMEVENT_PKGDIR)/$(VMEVENT_CLIENT_DEVEL_RPM): $(LIGHTWAVE_STAGE_DIR)
	@cd $(SRCROOT)/vmevent/build && make -f Makefile.bootstrap

vmevent-clean:
	@cd $(SRCROOT)/vmevent/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR) ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMEVENT_RPMS); \
	fi

vmdir-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_DEVEL_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_DEVEL_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_RPM):$(VMDIR_PKGDIR)/$(VMDIR_CLIENT_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_CLIENT_DEVEL_RPM):$(VMDIR_PKGDIR)/$(VMDIR_CLIENT_DEVEL_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDIR_SERVER_RPM):$(VMDIR_PKGDIR)/$(VMDIR_SERVER_RPM)
	$(CP) -f $< $@

$(VMDIR_PKGDIR)/$(VMDIR_CLIENT_RPM):$(VMDIR_PKGDIR)/$(VMDIR_SERVER_RPM)

$(VMDIR_PKGDIR)/$(VMDIR_CLIENT_DEVEL_RPM):$(VMDIR_PKGDIR)/$(VMDIR_SERVER_RPM)

$(VMDIR_PKGDIR)/$(VMDIR_SERVER_RPM):$(LIGHTWAVE_STAGE_DIR) vmevent-client-install
	@cd $(SRCROOT)/vmdir/build && make -f Makefile.bootstrap

vmdir-clean:
	@cd $(SRCROOT)/vmdir/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMDIR_RPMS); \
	fi

vmdns-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_DEVEL_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_DEVEL_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_RPM):$(VMDNS_PKGDIR)/$(VMDNS_CLIENT_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_CLIENT_DEVEL_RPM):$(VMDNS_PKGDIR)/$(VMDNS_CLIENT_DEVEL_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMDNS_SERVER_RPM):$(VMDNS_PKGDIR)/$(VMDNS_SERVER_RPM)
	$(CP) -f $< $@

$(VMDNS_PKGDIR)/$(VMDNS_CLIENT_RPM):$(VMDNS_PKGDIR)/$(VMDNS_SERVER_RPM)

$(VMDNS_PKGDIR)/$(VMDNS_CLIENT_DEVEL_RPM):$(VMDNS_PKGDIR)/$(VMDNS_SERVER_RPM)

$(VMDNS_PKGDIR)/$(VMDNS_SERVER_RPM):$(LIGHTWAVE_STAGE_DIR) vmdir-client-install
	@cd $(SRCROOT)/vmdns/build && make -f Makefile.bootstrap

vmdns-clean:
	@cd $(SRCROOT)/vmdns/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMDNS_RPMS); \
	fi

vmafd-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_DEVEL_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_PYTHON_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_DEVEL_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_PYTHON_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_PYTHON_RPM):$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_PYTHON_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_RPM):$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_CLIENT_DEVEL_RPM):$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_DEVEL_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMAFD_SERVER_RPM):$(VMAFD_PKGDIR)/$(VMAFD_SERVER_RPM)
	$(CP) -f $< $@

$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_RPM) : $(VMAFD_PKGDIR)/$(VMAFD_SERVER_RPM)

$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_DEVEL_RPM) : $(VMAFD_PKGDIR)/$(VMAFD_SERVER_RPM)

$(VMAFD_PKGDIR)/$(VMAFD_CLIENT_PYTHON_RPM) : $(VMAFD_PKGDIR)/$(VMAFD_SERVER_RPM)

$(VMAFD_PKGDIR)/$(VMAFD_SERVER_RPM): $(LIGHTWAVE_STAGE_DIR) vmdns-client-install
	@cd $(SRCROOT)/vmafd/build && make -f Makefile.bootstrap

vmafd-clean:
	@cd $(SRCROOT)/vmafd/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMAFD_RPMS); \
	fi

vmca-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_DEVEL_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_RPM) $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_DEVEL_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_RPM):$(VMCA_PKGDIR)/$(VMCA_CLIENT_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_CLIENT_DEVEL_RPM):$(VMCA_PKGDIR)/$(VMCA_CLIENT_DEVEL_RPM)
	$(CP) -f $< $@

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMCA_SERVER_RPM):$(VMCA_PKGDIR)/$(VMCA_SERVER_RPM)
	$(CP) -f $< $@

$(VMCA_PKGDIR)/$(VMCA_CLIENT_RPM):$(VMCA_PKGDIR)/$(VMCA_SERVER_RPM)

$(VMCA_PKGDIR)/$(VMCA_CLIENT_DEVEL_RPM):$(VMCA_PKGDIR)/$(VMCA_SERVER_RPM)

$(VMCA_PKGDIR)/$(VMCA_SERVER_RPM): $(LIGHTWAVE_STAGE_DIR) vmafd-client-install
	@cd $(SRCROOT)/vmca/build && make -f Makefile.bootstrap

vmca-clean:
	@cd $(SRCROOT)/vmca/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMCA_RPMS); \
	fi

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMSTS_SERVER_RPM):$(VMSTS_PKGDIR)/$(VMSTS_SERVER_RPM)
	$(CP) -f $< $@

$(VMSTS_PKGDIR)/$(VMSTS_SERVER_RPM): $(LIGHTWAVE_STAGE_DIR) vmca-client-install
	@cd $(SRCROOT)/vmidentity/build && make -f Makefile.bootstrap

vmsts-client-install: $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMSTS_CLIENT_RPM)
	$(RPM) -Uvh --force --nodeps $(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMSTS_CLIENT_RPM)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(VMSTS_CLIENT_RPM):$(VMSTS_PKGDIR)/$(VMSTS_CLIENT_RPM)
	$(CP) -f $< $@

$(VMSTS_PKGDIR)/$(VMSTS_CLIENT_RPM):$(VMSTS_PKGDIR)/$(VMSTS_SERVER_RPM)

vmsts-clean:
	@cd $(SRCROOT)/vmidentity/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(VMSTS_RPMS); \
	fi
	$(RMDIR) $(VMSTS_REST_VMDIR_CLIENT_TARGET)
	$(RMDIR) $(VMSTS_REST_VMDIR_COMMON_TARGET)
	$(RMDIR) $(VMSTS_REST_VMDIR_SERVER_TARGET)
	$(RMDIR) $(VMSTS_REST_IDM_TARGET)

$(LIGHTWAVE_STAGE_DIR)/x86_64/$(CFG_RPM) : $(CFG_PKGDIR)/$(CFG_RPM)
	$(CP) -f $< $@

$(CFG_PKGDIR)/$(CFG_RPM): $(LIGHTWAVE_STAGE_DIR) vmca-client-install vmsts-client-install
	@cd $(SRCROOT)/config/build && make -f Makefile.bootstrap

config-clean:
	@cd $(SRCROOT)/config/build && make -f Makefile.bootstrap clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR)/x86_64 ]; then \
	    cd $(LIGHTWAVE_STAGE_DIR)/x86_64 && $(RM) -f $(CFG_RPM); \
	fi

properties-clean:
	@cd $(VMSTS_PROPERTY_FILES) &&\
	$(RM) -f messages.properties &&\
	$(RM) -f messages_de.properties &&\
	$(RM) -f messages_es.properties &&\
	$(RM) -f messages_fr.properties &&\
	$(RM) -f messages_it.properties &&\
	$(RM) -f messages_ja.properties &&\
	$(RM) -f messages_ko.properties &&\
	$(RM) -f messages_nl.properties &&\
	$(RM) -f messages_pt.properties &&\
	$(RM) -f messages_ru.properties &&\
	$(RM) -f messages_zh_CN.properties &&\
	$(RM) -f messages_zh_TW.properties

diagnostics-folder-clean:
	@if [ -d $(VMSTS_DIAGNOSTICS_LIB) ]; then \
	    $(RMDIR) $(VMSTS_DIAGNOSTICS_LIB); \
	fi

resources-folder-clean:
	@if [ -d $(VMSTS_LWUI_SRC_MAIN_RESOURCES) ]; then \
	    $(RMDIR) $(VMSTS_LWUI_SRC_MAIN_RESOURCES); \
	fi

docker-clean:
	@$(RM) -rf $(LIGHTWAVE_STAGE_DIR)/docker-published

clean: config-clean vmca-clean vmafd-clean vmdns-clean vmdir-clean vmevent-clean \
		lw-server-clean lw-clients-clean vmsts-clean docker-clean lw-build-clean \
		properties-clean diagnostics-folder-clean resources-folder-clean
	@if [ -d $(LIGHTWAVE_STAGE_DIR) ]; then \
	    $(RMDIR) $(LIGHTWAVE_STAGE_DIR); \
	fi
	@$(RM) -f $(DOCKER_IMAGE)

$(LIGHTWAVE_STAGE_DIR):
	@$(MKDIR) -p $@/x86_64

