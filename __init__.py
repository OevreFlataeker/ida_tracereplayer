import sys
import idaapi
import ida_nalt
from PyQt5 import QtCore, QtGui, QtWidgets 
import idc

breakpoint()

class ColoringBB(): 
    flowchart = False 
    tgt_ea = 0 
    startea = 0 
    endea = 0 
    addr_fc = 0

    def __init__(self, addr_fc):
        self._set_fc_address(addr_fc)
        self._set_flowchart()

    def _set_fc_address(self, addr_fc):
        self.addr_fc = addr_fc 

    def _set_flowchart(self):
        f = idaapi.get_func(self.addr_fc)
        self.flowchart = idaapi.FlowChart(f)

    def coloring_bb(self, addr, color):
        self._set_bb_range(addr)
        for addr in range(self.startea, self.endea):
            idc.set_color(addr, idc.CIC_ITEM, color) # olive

    def _set_bb_range(self, addr):
        for block in self.flowchart:
            if block.start_ea <= addr and block.end_ea > addr:
                self.startea, self.endea = block.start_ea, block.end_ea
                breakbase = ida_nalt.get_imagebase()

class TraceReplayerClass(idaapi.PluginForm): 
	index = 0
	addr = []
	base = idaapi.get_imagebase() 

	def OnCreate(self, form): 
		# Get parent widget 

		self.parent = self.FormToPyQtWidget(form) # IDAPython 		
		self.PopulateForm()
		print(hex(self.base) )
 
	def PopulateForm(self): 
		# Create layout 
		layout = QtWidgets.QVBoxLayout() 
		
		# Create Table Widget  
		self.example_row = QtWidgets.QTableWidget()
		 
		column_names = ["Step", "BB Address", "Function"] 
		self.example_row.setColumnCount(len(column_names)) 
		self.example_row.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
		self.example_row.setRowCount(0) 
		self.example_row.setHorizontalHeaderLabels(column_names) 
		self.example_row.doubleClicked.connect(self.JumpSearch)
		self.example_row.verticalHeader().setVisible(False)
		layout.addWidget(self.example_row) 
		
		# Create selector
		layout2 = QtWidgets.QHBoxLayout()
		self.doitlabel = QtWidgets.QLabel()
		self.doitlabel.setText("Auto annotate:")
		layout2.addWidget(self.doitlabel)
		self.doitselector = QtWidgets.QCheckBox()		
		layout2.addWidget(self.doitselector)
		layout.addLayout(layout2)
		
		# Current Item

		layout3 = QtWidgets.QHBoxLayout()

		self.gotobtn = QtWidgets.QPushButton("Got to step")  		
		self.gotobtn.clicked.connect(self.GoTo)
		layout3.addWidget(self.gotobtn)
		
		self.txtindex = QtWidgets.QLineEdit()
		self.txtindex.setText(str(self.index))		
		self.txtindex.editingFinished.connect(self.GoTo)
		
		layout3.addWidget(self.txtindex)
		layout.addLayout(layout3)
				
		# Create Buttons
		layout4 = QtWidgets.QHBoxLayout()

		layout3a = QtWidgets.QHBoxLayout()
		
		self.runto = QtWidgets.QPushButton("Run to step")
		self.runto.clicked.connect(self.RunTo)
		layout3a.addWidget(self.runto)

		self.runindex = QtWidgets.QLineEdit()
		self.runindex.setText("")				
		layout3a.addWidget(self.runindex)
		layout.addLayout(layout3a)

		self.prevbtn = QtWidgets.QPushButton("Prev") 
		self.prevbtn.clicked.connect(self.BackTrace) 
		pn = QtGui.QPixmap("images/prev.png")
		ic = QtGui.QIcon("images/prev.png")
		self.prevbtn.setIcon(ic)
		


		layout4.addWidget(self.prevbtn)
		self.nextbtn = QtWidgets.QPushButton("Next") 
		self.nextbtn.isDefault = True
		self.nextbtn.clicked.connect(self.AdvanceTrace) 
		pn = QtGui.QPixmap("images/next.png")
		ic = QtGui.QIcon("images/next.png")
		self.nextbtn.setIcon(ic)
		layout4.addWidget(self.nextbtn) 
		layout.addLayout(layout4)

		self.loadTracebtn = QtWidgets.QPushButton("Load trace file") 
		self.loadTracebtn.clicked.connect(self.LoadTraceFile)
		layout.addWidget(self.loadTracebtn)
		# make our created layout the dialogs layout 
		self.parent.setLayout(layout) 

		self.btnfillfunctions = QtWidgets.QPushButton("Update functions") 
		self.btnfillfunctions.clicked.connect(self.UpdateFunctions)
		layout.addWidget(self.btnfillfunctions)
		# make our created layout the dialogs layout 
		self.parent.setLayout(layout) 
	
	def UpdateFunctions(self):

		for i in range(self.example_row.rowCount()):
			cur_addr = self.addr[i]
			f = idaapi.get_func(cur_addr)					
			self.example_row.setItem(i, 2, QtWidgets.QTableWidgetItem(idaapi.get_long_name(f.start_ea, idaapi.GN_VISIBLE))) # IDAPython 


	def RunTo(self):
		runto = int(self.runindex.text())
		if runto<self.index:
			print("Run to is less than current index. Not running")
			return
		while self.index<runto:
			self.index=self.index+1
			self.JumpSearchIndex(self.index)
			self.txtindex.setText(str(self.index+1))
			self.example_row.selectRow(self.index)

	def GoTo(self):
		self.index = int(self.txtindex.text())+1
		self.example_row.selectRow(self.index-1)
		self.JumpSearchIndex(self.index)

	def AdvanceTrace(self):
		self.index = self.index + 1
		print(f"New index: {self.index}")
		self.example_row.selectRow(self.index)		
		self.txtindex.setText(str(self.index+1))		
		self.JumpSearchIndex(self.index)

	def BackTrace(self):
		self.index = self.index - 1
		print(f"New index: {self.index}")
		self.example_row.selectRow(self.index)
		self.txtindex.setText(str(self.index+1))
		self.JumpSearchIndex(self.index)

	def fillListBox(self):
		step = 1
		self.example_row.setRowCount(len(self.addr))
		for elem in self.addr:
			col1 = QtWidgets.QTableWidgetItem(str(step))
			col1.setFlags(col1.flags() & ~QtCore.Qt.ItemIsEditable)			
			self.example_row.setItem(step-1, 0, col1) 
			
			col2 = QtWidgets.QTableWidgetItem(str(hex(elem)))
			col2.setFlags(col2.flags() & ~QtCore.Qt.ItemIsEditable)			
			self.example_row.setItem(step-1, 1, col2) # IDAPython 

			col3 = QtWidgets.QTableWidgetItem("")
			col2.setFlags(col2.flags() & ~QtCore.Qt.ItemIsEditable)			
			self.example_row.update()  
			self.example_row.setItem(step-1, 2, col3) # IDAPython 

			step = step + 1		
		
		#print(f"Added {step-1} items.")
		#print(f"Rowcount: {self.example_row.rowCount()}")
		
	def LoadTraceFile(self):
		options = QtWidgets.QFileDialog.Options()
		options |= QtWidgets.QFileDialog.DontUseNativeDialog
		fileName, _ = QtWidgets.QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","All Files (*);;Trace Files (*.log);;Text Files (*.txt)", options=options)
		#fileName = "D:\\trace.txt"
		if fileName:
			print(fileName)
			
			with open(fileName, "r") as f:
				l = f.readline().strip()
				if not l.startswith(";"):
					print("First line has to start with a ';' and include the filename!")
					return
				fn = l.split(" ")[0][1:]
				print(f"Trace file for {fn}")
				idbfile = ida_nalt.get_input_file_path() 
				if not fn in idbfile:
					print("IDB file does not seem to match trace file!")
					print(f"Trace file: {fn}")
					print(f"IDB file: {idbfile}")
					
				while (l!=None and l!=""):
					if l.startswith(";"):
						pass
					else:
						a = l.split("+")[1]
						self.addr.append(self.base+int(a,16))
					l = f.readline().strip()
			print(f"Loaded {len(self.addr)} trace steps")
			self.fillListBox()
	
	
		

	def JumpSearchIndex(self, index):		
		tt = self.example_row.item(index, 1)
		ea = int(tt.text(),16)
		#print(hex(ea)) 
		idaapi.jumpto(ea) # IDAPython  
		if self.doitselector.isChecked():
			cb = ColoringBB(ea)
			cb.coloring_bb(ea,0x00ff00)
			cur_comm = idc.get_cmt(ea,0)
			str2set = f"Step {self.index+1},"
			if cur_comm == None:
				cur_comm = str2set
			else:
				if not (str2set) in cur_comm:
					cur_comm = f"{cur_comm} {str2set}"
			idc.set_cmt(ea, cur_comm, 0)

	def JumpSearch(self, item):
		self.index = item.row()
		self.txtindex.setText(str(self.index+1))
		self.JumpSearchIndex(self.index)				

plg = TraceReplayerClass() 
plg.Show("daubsi's Tracefile Replayer") 
