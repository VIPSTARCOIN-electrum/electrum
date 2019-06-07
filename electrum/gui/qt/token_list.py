#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""

import webbrowser

import datetime
import binascii

from .util import *

from PyQt5.QtCore import Qt, QPersistentModelIndex, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QLabel, QMenu

from electrum.bitcoin import hash160_to_p2pkh
from electrum.i18n import _
from electrum.plugin import run_hook
from electrum.util import block_explorer_URL, TxMinedInfo


class TokenBalanceList(MyTreeView):
    filter_columns = [0, 1, 2]

    def __init__(self, parent=None):
        MyTreeView.__init__(self, parent, self.create_menu, 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.update()

    def update(self):
        item = self.currentIndex()
        current_key = item.data(Qt.UserRole) if item else None
        self.model().clear()
        self.update_headers([_('Name'), _('Bind Address'), _('Balance')])
        for key in sorted(self.parent.tokens.keys()):
            token = self.parent.tokens[key]
            balance_str = '{}'.format(token.balance / 10 ** token.decimals)
            # balance_str = format_satoshis(token.balance, is_diff=False, num_zeros=0,
            #                               decimal_point=token.decimals, whitespaces=True)
            item = SortableTreeWidgetItem([token.name, token.bind_addr, balance_str])
            item.setData(0, Qt.UserRole, token.contract_addr)
            item.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
            item.setTextAlignment(2, Qt.AlignRight | Qt.AlignVCenter)
            item.setFont(2, QFont(MONOSPACE_FONT))
            self.addTopLevelItem(item)
            if key == current_key:
                self.setCurrentItem(item)
        run_hook('update_tokens_tab', self)

    def doubleclick(self, item, column):
        bind_addr = item.text(1)
        contract_addr = item.data(0, Qt.UserRole)
        key = '{}_{}'.format(contract_addr, bind_addr)
        token = self.parent.tokens.get(key, None)
        self.parent.token_send_dialog(token)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedIndexes()
        multi_select = len(selected) > 1
        if not selected:
            menu.addAction(_("Add Token"), lambda: self.parent.token_add_dialog())
        elif not multi_select:
            item = selected[0]
            name = item.text(0)
            bind_addr = item.text(1)
            contract_addr = item.data(0, Qt.UserRole)
            key = '{}_{}'.format(contract_addr, bind_addr)
            token = self.parent.tokens.get(key, None)
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            menu.addAction(_("View Info"), lambda: self.parent.token_view_dialog(token))
            menu.addAction(_("Send"), lambda: self.parent.token_send_dialog(token))
            menu.addAction(_("Delete"), lambda: self.parent.delete_token(key))
            URL = block_explorer_URL(self.config, {'addr': bind_addr} , {'token': contract_addr})
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(URL))
        run_hook('create_tokens_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))


class TokenHistoryList(MyTreeView):
    filter_columns = [0, 1, 2]

    def __init__(self, parent=None):
        MyTreeView.__init__(self, parent, self.create_menu, 2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setModel(QStandardItemModel(self))
        self.update()

    def update(self):
        wallet = self.parent.wallet
        item = self.currentIndex()
        current_key = item.data(Qt.UserRole) if item else None
        self.model().clear()
        self.update_headers([_('Date'), _('Bind Address'), _('Token'), _('Amount')])
        for hist in wallet.get_token_history():
            _from, to, amount, token, txid, height, conf, timestamp, call_index, log_index = hist
            payout = False
            if _from == to:
                amount = 0
            if hash160_to_p2pkh(binascii.a2b_hex(to)) == token.bind_addr:
                balance_str = '+'
            else:
                balance_str = '-'
                payout = True
            balance_str += '{}'.format(amount / 10 ** token.decimals)
            tx_mined_status = TxMinedInfo(height, conf, timestamp, None)
            status, status_str = wallet.get_tx_status(txid, tx_mined_status)
            icon = self.icon_cache.get(":icons/" + TX_ICONS[status])

            item = SortableTreeWidgetItem(['', status_str, token.bind_addr, token.symbol, balance_str])
            item.setIcon(0, icon)
            item.setToolTip(0, str(conf) + " confirmation" + ("s" if conf != 1 else ""))
            item.setData(0, Qt.UserRole, txid)
            item.setTextAlignment(0, Qt.AlignLeft | Qt.AlignVCenter)
            self.addTopLevelItem(item)
            if txid == current_key:
                self.setCurrentItem(item)
            if payout:
                item.setForeground(3, QBrush(QColor("#BC1E1E")))
                item.setForeground(4, QBrush(QColor("#BC1E1E")))
        run_hook('update_token_hist_tab', self)

    def doubleclick(self, item, column):
        pass

    def format_date(self, d):
        return str(datetime.date(d.year, d.month, d.day)) if d else _('None')

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedIndexes()
        multi_select = len(selected) > 1
        if not selected:
            pass
        elif not multi_select:
            item = selected[0]
            txid = item.data(0, Qt.UserRole)
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy {}").format(column_title), lambda: self.parent.app.clipboard().setText(column_data))
            menu.addAction(_("Copy Transaction ID"), lambda: self.parent.app.clipboard().setText(txid))
            URL = block_explorer_URL(self.config, {'tx': txid})
            if URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(URL))
        run_hook('create_token_hist_menu', menu, selected)
        menu.exec_(self.viewport().mapToGlobal(position))
