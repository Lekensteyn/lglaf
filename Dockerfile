FROM ubuntu:latest
LABEL maintainer="David Manouchehri"

RUN useradd -m lglaf
WORKDIR /home/lglaf
ENV HOME /home/lglaf

RUN apt-get -y update && \
	DEBIAN_FRONTEND=noninteractive apt-get -y install git python-pip usbutils udev && \
	pip install --upgrade pip && \
	pip install pyusb && \
	su - lglaf -c "git clone https://github.com/Lekensteyn/lglaf.git" && \
	cp -v ~/lglaf/rules.d/42-usb-lglaf.rules /etc/udev/rules.d/ && \
	udevadm control --reload-rules || true && \
	udevadm trigger

# udev is sadly broken..
# USER lglaf
ENV PATH /home/lglaf/lglaf:$PATH

CMD ["/bin/bash"]
