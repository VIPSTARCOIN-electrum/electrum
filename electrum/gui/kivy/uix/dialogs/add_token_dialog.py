from datetime import datetime
from typing import NamedTuple, Callable

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button

from .question import Question
from electrum.gui.kivy.i18n import _

from electrum.util import parse_token_URI, InvalidTokenURI
from electrum.address_synchronizer import TX_HEIGHT_LOCAL

from .choice_dialog import ChoiceDialog

Builder.load_string('''
#:import partial functools.partial
#:import _ electrum.gui.kivy.i18n._

<AddTokenDialog>
    id: popup
    title: _('Add Token')
    contract_addr: ''
    BoxLayout:
        orientation: 'vertical'
        BoxLabel:
            text: _('Contract Address')
        SendReceiveBlueBottom:
            size_hint: 1, None
            height: self.minimum_height
            BlueButton:
                text: popup.contract_addr
                shorten: True
                on_release: Clock.schedule_once(lambda dt: app.show_info(_('Copy and paste the contract address using the Paste button, or use the camera to scan a QR code.')))
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                text: _('Paste')
                on_release: popup.do_paste()
            IconButton:
                id: qr
                size_hint: 0.6, 1
                on_release: Clock.schedule_once(lambda dt: app.scan_qr(on_complete=popup.on_qr))
                icon: 'atlas://electrum/gui/kivy/theming/light/camera'
        AddTokenItem:
            my_addr: app.wallet.get_addresses_sort_by_balance()[0]
            title: _('My Address:')
            description: str(self.my_addr)
            action: partial(root.address_select_dialog, self)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: 'OK'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.add_token()
                    popup.dismiss()
''')


class AddTokenDialog(Factory.Popup):

    def __init__(self, app):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.addresses = self.wallet.get_addresses_sort_by_balance()
        self.my_address = self.wallet.get_addresses_sort_by_balance()[0]
        self._address_select_dialog = None
        self.contract_addr = ''

    def address_select_dialog(self, item, dt):
        if self._address_select_dialog is None:
            def cb(addr):
                item.my_addr = addr
                self.my_address = addr
            self._address_select_dialog = ChoiceDialog(_('My Address'), self.addresses, self.my_address, cb)
        self._address_select_dialog.open()

    def add_token(self):
        contract_addr = self.contract_addr
        bind_addr = self.my_address
        if contract_addr == '':
            self.app.show_info(_("Contract Address is empty"))
            return
        try:
            r = self.app.network.run_from_another_thread(self.app.network.get_token_info(contract_addr))
            name = r.get('name')
            decimals = r.get('decimals')
            symbol = r.get('symbol')
            if not name or not symbol or not isinstance(decimals, int) or decimals is None:
                self.app.show_info(_("token info not valid: {} {} {}").format(name, symbol, decimals))
                return
            balance = self.app.network.run_from_another_thread(self.app.network.request_token_balance(bind_addr, contract_addr))
            token = [contract_addr, bind_addr, name, symbol, decimals, balance]
            self.app.set_token(token)
        except BaseException as e:
            import traceback, sys
            traceback.print_exc(file=sys.stderr)
            self.app.show_info(e)

    def search_token(self, contract_addr):
        try:
            token_data = self.app.network.run_from_another_thread(self.app.network.get_token_info(contract_addr))
        except:
            token_data = None
        if token_data:
            return True
        return False

    def do_paste(self):
        from electrum.bitcoin import base_decode, is_address
        data = self.app._clipboard.paste()
        if not data:
            self.app.show_info(_("Clipboard is empty"))
            return
        if is_address(data) or data.startswith('vipstarcoin:'):
            self.show_info(_("QR data is bitcoin URI."))
            return
        self.set_URI(data)

    def set_URI(self, text):
        if not self.app.wallet:
            self.payment_request_queued = text
            return
        try:
            uri = parse_token_URI(text)
        except InvalidTokenURI as e:
            self.app.show_error(_("Error parsing URI") + f":\n{e}")
            return
        address = uri.get('contract_addr', '')
        if not self.search_token(address):
            self.app.show_error(_("token not found"))
            self.contract_addr = ''
            return
        self.contract_addr = address

    def on_qr(self, data):
        from electrum.bitcoin import base_decode, is_address
        data = data.strip()
        if is_address(data) or data.startswith('vipstarcoin:'):
            self.show_info(_("QR data is bitcoin URI."))
            return
        if search_token(data) or data.startswith('vipstoken:'):
            self.set_URI(data)
            return
        # try to decode transaction
        from electrum.transaction import Transaction
        from electrum.util import bh2u
        try:
            text = bh2u(base_decode(data, None, base=43))
            tx = Transaction(text)
            tx.deserialize()
        except:
            tx = None
        if tx:
            self.show_info(_("QR data is transaction."))
            return
        # show error
        self.show_error(_("Unable to decode QR data"))
