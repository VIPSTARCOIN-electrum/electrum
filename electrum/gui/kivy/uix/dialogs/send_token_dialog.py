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

from electrum.util import InvalidPassword, InvalidTokenURI, parse_token_URI
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.wallet import CannotBumpFee


Builder.load_string('''

<SendTokenDialog>
    id: popup
    title: _('Send Token')
    name: ''
    symbol: ''
    max_amount: ''
    to_addr: ''
    contract_addr: ''
    amount: ''
    gas_limit: ''
    gas_price: ''
    is_pr: False
    BoxLayout:
        orientation: 'vertical'
        SendReceiveBlueBottom:
            id: blue_bottom
            size_hint: 1, None
            height: self.minimum_height
            BoxLayout:
                size_hint: 2, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/pen'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.name
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/globe'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.to_addr if popup.to_addr else _('Send to address')
                    on_release: Clock.schedule_once(lambda dt: app.show_info(_('Copy and paste the recipient address using the Paste button, or use the camera to scan a QR code.')))
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/calculator'
                    opacity: 0.7
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.amount if popup.amount else _('Amount')
                    on_release: Clock.schedule_once(lambda dt: app.token_amount_dialog(popup, root.symbol, root.max_amount, True))
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/star_big_inactive'
                    opacity: 0.7
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: _('gas limit:') + popup.gas_limit
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/star_big_inactive'
                    opacity: 0.7
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: _('gas price:') + popup.gas_price
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
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
            Button:
                text: 'Pay'
                size_hint: 0.5, None
                height: '48dp'
                on_release: 
                    root.do_send()
                    popup.dismiss()
''')


class SendTokenDialog(Factory.Popup):

    def __init__(self, app, token):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.token = token
        self.name = token.name
        self.symbol = token.symbol
        self.decimals = token.decimals
        self.decimals_str = "{}".format(token.decimals)
        self.balance = token.balance
        self.bind_addr = token.bind_addr
        self.contract_addr = token.contract_addr
        self.balance = token.balance
        self.max_amount = "{}".format(token.balance / 10 ** token.decimals)
        self.to_addr = ''
        self.amount = ''
        self.gas_limit = '250000'
        self.gas_price = '0.00000040'
        self.is_pr = False

    def do_paste(self):
        from electrum.bitcoin import is_p2pkh
        data = self.app._clipboard.paste()
        if not data:
            self.app.show_info(_("Clipboard is empty"))
            return
        if is_p2pkh(data):
            uri = "vipstoken:{}?to_addr={}".format(self.contract_addr, data)
            self.set_URI(uri)
            return
        # try to decode as URI/address
        self.set_URI(data)

    def match_token(self, contract_addr):
        return self.contract_addr == contract_addr

    def set_URI(self, text):
        from electrum.bitcoin import is_p2pkh
        if not self.app.wallet:
            self.payment_request_queued = text
            return
        try:
            uri = parse_token_URI(text)
        except InvalidTokenURI as e:
            self.app.show_error(_("Error parsing URI") + f":\n{e}")
            return
        address = uri.get('contract_addr', '')
        to_addr = uri.get('to_addr', '')
        amount = uri.get('amount', '')
        if not self.match_token(address):
            self.app.show_error(_("token doesn't mutch"))
            return
        self.amount = self.app.format_token_amount_and_units(amount, self.decimals, self.symbol)if amount else ''
        if not is_p2pkh(to_addr):
            self.app.show_error(_("send to address is miss."))
        else:
            self.to_addr = to_addr

    def on_qr(self, data):
        from electrum.bitcoin import base_decode, is_p2pkh, is_address
        data = data.strip()
        if is_p2pkh(data):
            uri = "vipstoken:{}?send_to={}".format(self.contract_addr, data)
            self.set_URI(uri)
            return
        if is_address(data):
            self.show_info(_("QR data isn't p2pkh address."))
            return
        if data.startswith('vipstarcoin:'):
            self.show_info(_("QR data is bitcoin URI."))
            return
        if match_token(data):
            self.show_info(_("QR data is Contract Address."))
            return
        if data.startswith('vipstoken:'):
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

    def do_send(self):
        from electrum.bitcoin import is_p2pkh, is_hash160, b58_address_to_hash160, bh2u, TYPE_SCRIPT
        from electrum.transaction import opcodes, contract_script, TxOutput
        address = str(self.to_addr)
        if not address:
            self.app.show_error(_('Recipient not specified.') + ' ' + _('Please scan a Bitcoin address or a payment request'))
            return
        if is_p2pkh(address):
            addr_type, hash160 = b58_address_to_hash160(address)
            hash160 = bh2u(hash160)
        elif is_hash160(address):
            hash160 = address.lower()
        else:
            self.app.show_error(_('Invalid Bitcoin Address') + ':\n' + address)
            return
        if address == self.bind_addr:
            self.app.show_error(_('You can not send to bind address!'))
            return
        try:
            amount = self.app.get_token_amount(self.amount, self.symbol, self.decimals)
        except:
            self.app.show_error(_('Invalid amount') + ':\n' + self.screen.amount)
            return
        print(amount)
        datahex = 'a9059cbb{}{:064x}'.format(hash160.zfill(64), amount)
        tx_desc = _('Pay out {} {}').format(amount / (10 ** self.decimals), self.symbol)
        gas_limit = int(self.gas_limit)
        gas_price = int(float(self.gas_price) * (10 ** 8))
        script = contract_script(gas_limit, gas_price, datahex, self.contract_addr, opcodes.OP_CALL)
        outputs = [TxOutput(TYPE_SCRIPT, script, 0), ]
        amount = sum(map(lambda x:x[2], outputs))
        self._do_send(amount, tx_desc, outputs, gas_limit * gas_price)

    def _do_send(self, amount, desc, outputs, gas_fee):
        from electrum.plugin import run_hook
        from electrum import simple_config
        # make unsigned transaction
        config = self.app.electrum_config
        coins = self.app.wallet.get_spendable_coins(None, config)
        sender = self.bind_addr
        try:
            tx = self.app.wallet.make_unsigned_transaction(coins, outputs, config, None,
                                                           change_addr=sender,
                                                           gas_fee=gas_fee,
                                                           sender=sender)
        except NotEnoughFunds:
            self.app.show_error(_("Insufficient funds"))
            return
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.app.show_error(str(e))
            return
        fee = tx.get_fee()
        msg = [
            _(desc),
            _("Mining fee") + ": " + self.app.format_amount_and_units(fee - gas_fee),
            _("Gas fee") + ": " + self.app.format_amount_and_units(gas_fee),
        ]
        x_fee = run_hook('get_tx_extra_fee', self.app.wallet, tx)
        if x_fee:
            x_fee_address, x_fee_amount = x_fee
            msg.append(_("Additional fees") + ": " + self.app.format_amount_and_units(x_fee_amount))

        feerate_warning = simple_config.FEERATE_WARNING_HIGH_FEE
        if fee > feerate_warning * tx.estimated_size() / 1000:
            msg.append(_('Warning') + ': ' + _("The fee for this transaction seems unusually high."))
        msg.append(_("Enter your PIN code to proceed"))
        self.app.protected('\n'.join(msg), self.send_tx, (tx, desc))

    def send_tx(self, tx, desc, password):
        if self.app.wallet.has_password() and password is None:
            return
        def on_success(tx):
            if tx.is_complete():
                self.app.broadcast(tx, None)
                self.app.wallet.set_label(tx.txid(), desc)
            else:
                self.app.tx_dialog(tx)
        def on_failure(error):
            self.app.show_error(error)
        if self.app.wallet.can_sign(tx):
            self.app.show_info("Signing...")
            self.app.sign_tx(tx, password, on_success, on_failure)
        else:
            self.app.tx_dialog(tx)
