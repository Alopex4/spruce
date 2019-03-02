#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from shineMainWindow import ShineMainWindow


class BrightMainWindow(ShineMainWindow):
    def __init__(self):
        super().__init__()
        self.signalSlotMap()

    def signalSlotMap(self):
        """
            Signal and slot mapping
            Widget communicate with each other relationship mapping
        """
        pass

    def refreshBtnClick(self):
        """
            Clicked the `refresh` button
            1. Acquire local netork work information
                * Network Interface name
                * Network IP
                * Network MAC
                * Network Vendor --> via MAC and OUI.csv
                * Network Mask
            2. Acquire gateway network information
                * Gateway IP
                * Gateway MAC
                * Gateway Vendor --> via MAC and OUI.csv
        """

        # Task 1
        # Acquire local info
