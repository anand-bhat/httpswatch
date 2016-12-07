// Formatting function for row details
function format(row) {
	'use strict';
	return '<table><tr><td>SSL Labs report: <a target="_blank" href="https://www.ssllabs.com/ssltest/analyze.html?d=' + row[2] + '&ignoreMismatch=on">' + row[2] + '</a></td></tr></table>';
}

function drawChartCountsByOrg() {
	'use strict';
	if (chartDataCountsByOrg === undefined) {
		return;
	}

	var data = google.visualization.arrayToDataTable(chartDataCountsByOrg);

	var options = {
		bar: {groupWidth: 30},
		chartArea: {
			bottom: 50,
			top: 50
		},
		hAxis: {
			minValue: 0,
			ticks: [0, 0.25, 0.5, 0.75, 1],
			textStyle: {fontSize: 14}
		},
		height: (100 + (60 * data.getNumberOfRows())),
		isStacked: 'percent',
		legend: {
			maxLines: 1,
			position: 'top',
			textStyle: {fontSize: 14}
		},
		series: {
			0: {color: 'Green'},
			1: {color: 'YellowGreen'},
			2: {color: 'LightGreen'},
			3: {color: 'Orange'},
			4: {color: 'Orange'},
			5: {color: 'Orange'},
			6: {color: 'Orange'},
			7: {color: 'Red'},
			8: {color: 'Red'},
			9: {color: 'Red'},
			10: {color: 'Gray'},
			11: {color: 'Gray'}
		},
		tooltip: {
			textStyle: {fontSize: 14},
			showColorCode: true
		},
		vAxis: {
			textStyle: {fontSize: 14}
		}
	};

	var chart = new google.visualization.BarChart(document.getElementById('chartCountsByOrg'));
	chart.draw(data, options);
}

// Sort function for SSL Grade to show A+ first
jQuery.extend(jQuery.fn.dataTableExt.oSort, {
	'enumgrade-pre': function (a) {
		'use strict';
		switch (a) {
		case 'A+':
			return 1;
		case 'A':
			return 2;
		case 'A-':
			return 3;
		case 'B':
			return 4;
		case 'C':
			return 5;
		case 'D':
			return 6;
		case 'E':
			return 7;
		case 'T/ A+':
			return 8;
		case 'T/ A':
			return 9;
		case 'T/ A-':
			return 10;
		case 'T/ B':
			return 11;
		case 'T/ C':
			return 12;
		case 'T/ D':
			return 13;
		case 'T/ E':
			return 14;
		case 'T/ F':
			return 15;
		case 'F':
			return 16;
		case 'No HTTPS':
			return 17;
		case 'Scan error':
			return 18;
		case 'Could not connect':
			return 19;
		case 'Not scanned':
			return 20;
		case 'Unknown domain':
			return 21;
		default:
			return 22;
		}
	},

	'enumgrade-asc': function (a, b) {
		'use strict';
		return ((a < b) ? -1 : ((a > b) ? 1 : 0));
	},

	'enumgrade-desc': function (a, b) {
		'use strict';
		return ((a < b) ? 1 : ((a > b) ? -1 : 0));
	}
});

$(document).ready(function () {
	'use strict';
	var table = $('#httpsdata').DataTable({
		columns: [
			{
				className: 'details-control',
				data: null,
				defaultContent: '',
				orderable: false
			},
			{title: 'Organization'},
			{title: 'Host'},
			{title: 'IP Address'},
			{title: 'SSL Labs Grade'},
			{title: 'Test Date', className: 'center'},
			{title: 'Status Message'},
			{title: 'Industry'},
			{title: 'Host Purpose'},
			{title: 'HTTPS Behavior'},
			{title: 'Issue Report', className: 'center', orderable: false},
			{title: '[F] Vulnerable to Heartbleed'},
			{title: '[F] Vulnerable to CVE-2014-0224'},
			{title: '[F] Vulnerable to CVE-2016-2107'},
			{title: '[F] Vulnerable to FREAK'},
			{title: '[F] Vulnerable to Logjam'},
			{title: '[F] Vulnerable to POODLE (TLS)'},
			{title: '[F] Vulnerable to DROWN'},
			{title: '[F] Supports SSLv2'},
			{title: '[F] Supports Anonymous suites'},
			{title: '[F] Only supports RC4 suites'},
			{title: '[F] Supports Insecure renegotiation'},
			{title: '[F] No support for TLS'},
			{title: '[T] Untrusted certificate'},
			{title: '[C] Vulnerable to POODLE (SSLv3)'},
			{title: '[C] Lacks support for TLSv1.2'},
			{title: '[C] Uses RC4 with modern protocols'},
			{title: '[B] Supports RC4'},
			{title: '[B] Supports SSLv3'},
			{title: '[B] Uses weak DH'},
			{title: '[B] Has incomplete chain'},
			{title: '[B] Has weak private key'},
			{title: '[A-] Lacks Forward Secrecy'},
			{title: '[A-] Lacks Secure Renegotiation'}
		],
		columnDefs: [
			{
				// Show link to SSL Labs scan. Link to site rather than endpoint to see messages about inconsistent endpoints
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}
					var gradeClass;
					switch (data) {
					case 'A+':
						gradeClass = 'grade-green';
						break;
					case 'A':
						gradeClass = 'grade-yellowgreen';
						break;
					case 'A-':
						gradeClass = 'grade-lightgreen';
						break;
					case 'B':
					case 'C':
					case 'D':
					case 'E':
						gradeClass = 'grade-orange';
						break;
					case 'Unknown domain':
					case 'Could not connect':
					case 'Scan error':
					case 'Not scanned':
						gradeClass = 'grade-gray';
						break;
					default:
						gradeClass = 'grade-red';
					}
					return '<div class="grade ' + gradeClass + '"><a target="_blank" class="white" href="https://www.ssllabs.com/ssltest/analyze.html?d=' + row[2] + '&ignoreMismatch=on">' + data + '</a></div>';
				},
				targets: 4
			},
			{
				// Show link to Github issue report
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}

					if (data !== '' && data !== '-') {
						return '<a target="_blank" href="' + data + '">View</a>';
					}
					if (row[4] === 'A' || row[4] === 'A-' || row[4] === 'A+' || row[4] === 'Could not connect' || row[4] === 'Scan error' || row[4] === 'Not scanned'  || row[4] === 'Unknown domain') {
						return data;
					}
					return '<a target="_blank" href="https://github.com/anand-bhat/httpswatch/issues/new">Create</a>';
				},
				targets: 10
			},
			{
				// For issues, show 'No' in green, 'Yes' in red highlight
				render: function (data, type, row, meta) {
					if (type !== 'display') {
						return data;
					}
					var cellClass;
					switch (data) {
					case 'Yes':
						cellClass = 'center badhighlight';
						break;
					case 'No':
						cellClass = 'center good';
						break;
					default:
						cellClass = 'center';
					}
					return '<div class="' + cellClass + '">' + data + '</div>';
				},
				targets: [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]
			},
			{
				// Add title to cells
				createdCell: function (cell, cellData, rowData, rowIndex, colIndex) {
					$(cell).prop('title', 'Organization: ' + rowData[1] + '\r\nHost: ' + rowData[2] + '\r\nIP Address: ' + rowData[3] + '\r\nSSL Labs Grade: ' + rowData[4]);
				},
				targets: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33]
			},
			{type: 'enumgrade', targets: 4},
			{visible: false, targets: [0, 5, 6, 7, 8, 9, 10]}
		],
		data: dataSet,
		deferRender: true,
		fixedHeader: { footer: true, header: true },
		initComplete: function () {
			this.api().columns().every(function () {
				var column = this;

				if (column.index() === 0 || column.index() === 10) {
					// Do not add filters to 0th and 10th column (expander and report link)
					$(column.footer()).empty();
					return;
				}

				var select = $('<select><option value="">No Choice</option></select>')
					.appendTo($(column.footer()).empty())
					.on('change', function () {
						var val = $.fn.dataTable.util.escapeRegex($(this).val());

						if (val === '') {
							val = '.*.';
						}

						column.search(val ? '^' + val + '$' : '-', true, false).draw();
					});

				column.data().unique().sort().each(function (d, j) {
					select.append('<option value="' + d + '">' + d + '</option>');
				});
			});
		},
		lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']],
		order: [[1, 'asc'], [2, 'asc'], [3, 'asc']]
	});

	// Expand/ collapse details section
	$('#httpsdata tbody').on('click', 'td.details-control', function () {
		var tr = $(this).closest('tr');
		var row = table.row(tr);

		if (row.child.isShown()) {
			// Close this row
			row.child.hide();
			tr.removeClass('shown');
		} else {
			// Open this row
			row.child(format(row.data())).show();
			tr.addClass('shown');
		}
	});

	// Toggle column visibility and option state
	$('a.toggle-column').on('click', function (e) {
		e.preventDefault();

		var column = table.column($(this).attr('data-column'));
		if (column.visible()) {
			$(this).css('text-decoration', 'line-through');
			//$(this).toggleClass('strikethrough'); //Delayed repaint
			column.visible(false);
		} else {
			$(this).css('text-decoration', 'none');
			//$(this).toggleClass('strikethrough'); //Delayed repaint
			column.visible(true);
		}
		table.fixedHeader.adjust();
	});

	// Toggle options section visibility
	$('#toggleColumns').on('click', function (e) {
		e.preventDefault();

		if ($('#toggleColumnsSection').is(':visible')) {
			$('#toggleColumnsSection').hide();
			$(this).text('[show section]');
		}
		else {
			$('#toggleColumnsSection').show();
			$(this).text('[hide section]');
		}
	});

		// Toggle chart section visibility
	$('#toggleChartCountsByOrg').on('click', function (e) {
		e.preventDefault();

		if ($('#chartCountsByOrg').is(':visible')) {
			$('#chartCountsByOrg').hide();
			$(this).text('[show section]');
		}
		else {
			$('#chartCountsByOrg').show();
			$(this).text('[hide section]');
		}
	});

	google.charts.load('current', {packages: ['corechart']});
	google.charts.setOnLoadCallback(drawChartCountsByOrg);
});